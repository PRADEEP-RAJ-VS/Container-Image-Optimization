import os
import docker
import tempfile
import tarfile
import io
import time
import logging
import re
import boto3
from dotenv import load_dotenv
from flask import Flask, request, render_template, jsonify
from typing import Dict, Any, List
from analysis import ImageAnalyzer
from slimming import generate_slimming_recommendations
from utils import safe_remove_container

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Initialize Docker client with error handling
try:
    client = docker.from_env()
    client.ping()  # Test connection
    logger.info("Docker client initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Docker client: {e}")
    client = None

# Initialize AWS ECR client
try:
    ecr_client = boto3.client(
        'ecr',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_DEFAULT_REGION', 'ap-south-1')
    )
    logger.info("ECR client initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize ECR client: {e}")
    ecr_client = None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/ecr-images", methods=["GET"])
def list_ecr_images():
    """List available ECR images"""
    if not ecr_client:
        return jsonify({"error": "ECR client not available. Please check AWS credentials."}), 500
    
    try:
        logger.info("Fetching ECR repositories...")
        images = []
        
        # Get all repositories
        repositories = ecr_client.describe_repositories()['repositories']
        logger.info(f"Found {len(repositories)} ECR repositories")
        
        for repo in repositories:
            repo_name = repo['repositoryName']
            repo_uri = repo['repositoryUri']
            
            try:
                # Get images for this repository
                image_details = ecr_client.list_images(
                    repositoryName=repo_name,
                    filter={'tagStatus': 'TAGGED'}
                )
                
                for img in image_details['imageIds']:
                    tag = img.get('imageTag', 'latest')
                    if tag:  # Only include tagged images
                        full_uri = f"{repo_uri}:{tag}"
                        images.append({
                            'name': f"{repo_name}:{tag}",
                            'uri': full_uri,
                            'repository': repo_name,
                            'tag': tag,
                            'registry': repo_uri.split('/')[0]
                        })
                        
            except Exception as e:
                logger.warning(f"Failed to list images for repository {repo_name}: {e}")
                continue
        
        # Sort images by repository name and tag
        images.sort(key=lambda x: (x['repository'], x['tag']))
        
        logger.info(f"Successfully retrieved {len(images)} ECR images")
        return jsonify({
            "success": True,
            "images": images,
            "total": len(images)
        })
        
    except Exception as e:
        logger.error(f"Failed to list ECR images: {e}")
        return jsonify({"error": f"Failed to list ECR images: {str(e)}"}), 500

@app.route("/analyze", methods=["POST"])
def analyze():
    if not client:
        return jsonify({"error": "Docker client not available"}), 500
    
    # Get image from form data or JSON
    logger.info(f"Request content type: {request.content_type}")
    logger.info(f"Request is_json: {request.is_json}")
    logger.info(f"Form data: {dict(request.form)}")
    
    image = None
    if request.is_json:
            image = request.json.get("image")
            logger.info(f"Got image from JSON: {image}")
    else:
            image = request.form.get("image")
    logger.info(f"Got image from form: {image}")
        
    if not image or not image.strip():

        logger.error("No image provided in request")
        return jsonify({"error": "No image provided"}), 400

    image = image.strip()
    logger.info(f"Using image: {image}")

    container = None
    try:
        logger.info(f"Starting analysis for image: {image}")
        
        # Ensure image exists locally
        try:
            client.images.pull(image)
            logger.info(f"Successfully pulled image: {image}")
        except Exception as e:
            logger.error(f"Failed to pull image {image}: {e}")
            return jsonify({"error": f"Failed to pull image: {str(e)}"}), 500

        log_path = f"/tmp/file-access-{next(tempfile._get_candidate_names())}.log"

        # 1️⃣ Start container with shell like old.py
        container = client.containers.run(
            image,
            command="/bin/sh",
            detach=True,
            tty=True,
            remove=False,  # Don't auto-remove so we can clean up manually
            cap_add=['SYS_PTRACE'],
            security_opt=['apparmor=unconfined', 'seccomp=unconfined']
        )
        container_id = container.id[:12]
        logger.info(f"Started container: {container_id}")

        # Detect OS and package manager
        os_info = {
            "name": "Unknown",
            "version": "Unknown",
            "architecture": "Unknown",
            "package_manager": "unknown",
            "base_image": "Unknown"
        }
        try:
            os_release = container.exec_run("cat /etc/os-release")
            if os_release.exit_code == 0 and os_release.output:
                lines = os_release.output.decode("utf-8", errors="ignore").strip().split('\n')
                data = {}
                for line in lines:
                    if '=' in line and not line.strip().startswith('#'):
                        k, v = line.split('=', 1)
                        data[k.strip()] = v.strip().strip('"')
                os_info["name"] = data.get("NAME", os_info["name"])
                os_info["version"] = data.get("VERSION_ID", data.get("VERSION", os_info["version"]))
                os_info["base_image"] = data.get("PRETTY_NAME", os_info["base_image"])
        except Exception as e:
            logger.warning(f"Failed to read /etc/os-release: {e}")

        # Detect architecture
        try:
            arch_res = container.exec_run("uname -m")
            if arch_res.exit_code == 0 and arch_res.output:
                os_info["architecture"] = arch_res.output.decode().strip()
        except Exception:
            pass

        # Detect package manager
        try:
            if container.exec_run("which apt").exit_code == 0:
                os_info["package_manager"] = "apt"
            elif container.exec_run("which apk").exit_code == 0:
                os_info["package_manager"] = "apk"
            elif container.exec_run("which dnf").exit_code == 0:
                os_info["package_manager"] = "dnf"
            elif container.exec_run("which yum").exit_code == 0:
                os_info["package_manager"] = "yum"
        except Exception:
            pass

        # Check if strace is available in the container
        strace_check = container.exec_run("which strace")
        logger.info(f"Strace check exit code: {strace_check.exit_code}")
        
        if strace_check.exit_code != 0:
            logger.info("strace not found, trying to install...")
            # Try to install strace
            install_result = container.exec_run("apt-get update && apt-get install -y strace", user="root")
            logger.info(f"strace install exit code: {install_result.exit_code}")
            
            if install_result.exit_code != 0:
                logger.info("Could not install strace, using fallback analysis")
                return analyze_without_strace(container, container_id)

        # 2️⃣ Run strace inside container - detect image type and run appropriate commands
        logger.info("Detecting image type and determining analysis strategy...")
        
        # Check what type of image this is
        python_check = container.exec_run("which python3 || which python")
        node_check = container.exec_run("which node")
        java_check = container.exec_run("which java")
        
        strace_cmd = None
        
        if python_check.exit_code == 0:
            logger.info("Detected Python image")
            # Look for Python applications
            app_check = container.exec_run("find /app -name '*.py' | head -1")
            app_file = None
            
            if app_check.exit_code == 0 and app_check.output:
                found_app = app_check.output.decode().strip()
                if found_app:
                    app_file = found_app
                    logger.info(f"Found Python app: {app_file}")
            
            # If no app found in /app, try common locations
            if not app_file:
                for possible_app in ["/app/app.py", "/app/main.py", "/usr/src/app/app.py", "/code/app.py", "/app/run.py"]:
                    check_result = container.exec_run(f"test -f {possible_app}")
                    if check_result.exit_code == 0:
                        app_file = possible_app
                        logger.info(f"Found Python app at: {app_file}")
                        break
            
            if app_file:
                strace_cmd = f"strace -f -e trace=file -o {log_path} python3 {app_file}"
            else:
                # Trace Python import system
                strace_cmd = f"strace -f -e trace=file -o {log_path} python3 -c 'import sys; import os; import json; print(\"Python system traced\")'"
                
        elif node_check.exit_code == 0:
            logger.info("Detected Node.js image")
            # Look for Node.js applications
            package_check = container.exec_run("find /app -name 'package.json' | head -1")
            if package_check.exit_code == 0 and package_check.output:
                package_path = package_check.output.decode().strip()
                app_dir = package_path.replace('/package.json', '')
                strace_cmd = f"strace -f -e trace=file -o {log_path} node {app_dir}/index.js || node {app_dir}/app.js || node {app_dir}/server.js"
            else:
                strace_cmd = f"strace -f -e trace=file -o {log_path} node -e 'console.log(\"Node.js system traced\")'"
                
        elif java_check.exit_code == 0:
            logger.info("Detected Java image")
            # Look for Java applications
            jar_check = container.exec_run("find /app -name '*.jar' | head -1")
            if jar_check.exit_code == 0 and jar_check.output:
                jar_file = jar_check.output.decode().strip()
                strace_cmd = f"strace -f -e trace=file -o {log_path} java -jar {jar_file}"
            else:
                strace_cmd = f"strace -f -e trace=file -o {log_path} java -version"
        else:
            logger.info("Detected generic/base image (Ubuntu, Alpine, etc.)")
            # For base images, trace common system operations
            strace_cmd = f"strace -f -e trace=file -o {log_path} sh -c 'ls -la /; find /usr/bin -name \"*\" | head -20; echo \"Base system traced\"'"
        
        logger.info(f"Running strace command: {strace_cmd}")
        
        # Use the API approach like old.py for better control
        exec_result = container.exec_run(strace_cmd, detach=True)
        logger.info(f"Strace command started, exit code: {exec_result.exit_code}")
        
        # Give app time to run & generate logs
        time.sleep(10)

        # 3️⃣ Copy log file from container
        try:
            bits, _ = container.get_archive(log_path)
            logger.info("Successfully retrieved log file from container")
        except Exception as e:
            logger.error(f"Failed to get log file: {e}")
            # Try alternative approach - get file listing directly
            return analyze_without_strace(container, container_id)

        # Process the tar archive
        file_like = io.BytesIO(b"".join(chunk for chunk in bits))
        log_content = ""
        try:
            with tarfile.open(fileobj=file_like) as tar:
                member = tar.getmembers()[0]
                extracted = tar.extractfile(member)
                log_content = extracted.read().decode("utf-8", errors="ignore") if extracted else ""
        except Exception as e:
            logger.error(f"Failed to extract log content: {e}")
            return analyze_without_strace(container, container_id)

        # 4️⃣ Parse accessed files using old.py approach
        accessed_files = set()
        for line in log_content.splitlines():
            # Look for open() and stat() calls like in old.py
            if 'open(' in line or 'stat(' in line or 'openat(' in line:
                parts = line.split('"')
                if len(parts) > 1:
                    file_path = parts[1]
                    # Filter out non-file paths and system calls
                    if file_path.startswith('/') and not any(x in file_path for x in ['/dev/', '/proc/', '/sys/']):
                        accessed_files.add(file_path)

        accessed_files = list(accessed_files)
        logger.info(f"Found {len(accessed_files)} accessed files from strace")

        # 5️⃣ List all files in container with improved discovery for all image types
        logger.info("Starting comprehensive file discovery...")
        all_files = []
        
        # Try multiple approaches for file discovery - more comprehensive for base images
        find_commands = [
            # Comprehensive discovery for base images
            "find / -type f -not -path '/dev/*' -not -path '/proc/*' -not -path '/sys/*' -not -path '/tmp/*' 2>/dev/null | head -15000",
            # Focus on system directories
            "find /usr /bin /sbin /lib /lib64 /etc /opt /var -type f 2>/dev/null | head -10000",
            # Ubuntu/Debian specific
            "find /usr/share /usr/lib /usr/bin /usr/sbin -type f 2>/dev/null | head -8000",
            # Fallback to basic system files
            "find /usr -type f 2>/dev/null | head -5000"
        ]
        
        for i, cmd in enumerate(find_commands):
            logger.info(f"Trying file discovery method {i+1}: {cmd}")
            try:
                exec_ls = container.exec_run(cmd)
                logger.info(f"File discovery method {i+1} exit code: {exec_ls.exit_code}")
                
                if exec_ls.exit_code == 0 and exec_ls.output:
                    files = [f.strip() for f in exec_ls.output.decode("utf-8", errors="ignore").splitlines() if f.strip()]
                    if files:
                        all_files = files
                        logger.info(f"Found {len(all_files)} files using method {i+1}")
                        break
            except Exception as e:
                logger.warning(f"File discovery method {i+1} failed: {e}")
                continue
        
        if not all_files:
            logger.warning("All file discovery methods failed, trying basic directory listing")
            # Try basic directory listing as last resort
            basic_dirs = ['/usr', '/bin', '/sbin', '/lib', '/etc', '/opt']
            for dir_path in basic_dirs:
                try:
                    exec_ls = container.exec_run(f"find {dir_path} -type f 2>/dev/null | head -2000")
                    if exec_ls.exit_code == 0 and exec_ls.output:
                        files = [f.strip() for f in exec_ls.output.decode("utf-8", errors="ignore").splitlines() if f.strip()]
                        all_files.extend(files)
                except Exception as e:
                    logger.warning(f"Failed to list {dir_path}: {e}")
                    continue
            
            if not all_files:
                logger.warning("Zero-proof fallback: running broad find without limits")
            try:
                exec_ls = container.exec_run("sh -lc \"find / -xdev -type f -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' 2>/dev/null\"")
                if exec_ls.exit_code == 0 and exec_ls.output:
                    all_files = [f.strip() for f in exec_ls.output.decode("utf-8", errors="ignore").splitlines() if f.strip()]
            except Exception as e:
                logger.warning(f"Broad find failed: {e}")

        if not all_files:
            logger.warning("Final fallback: parse recursive ls output")
            try:
                exec_ls = container.exec_run("sh -lc 'ls -lRa / 2>/dev/null | awk \"$1 ~ /^[^-]/ {next} {print \\$9}\" | sed -n \"s,^$,SKIP,p; t; p\"' ")
                if exec_ls.exit_code == 0 and exec_ls.output:
                    candidates = [f.strip() for f in exec_ls.output.decode("utf-8", errors="ignore").splitlines() if f.strip() and f != 'SKIP']
                    # Prefix paths that aren't absolute from ls context isn't reliable; keep absolute only
                    all_files = [p for p in candidates if p.startswith('/')]
            except Exception as e:
                logger.warning(f"Recursive ls parsing failed: {e}")

        if not all_files:
            logger.warning("Using accessed files as last reference to avoid zeros")
            all_files = list(accessed_files)

        # Calculate file categories with improved logic for all image types
        system_files = [f for f in all_files if any(f.startswith(p) for p in ['/bin/', '/sbin/', '/lib/', '/usr/', '/lib64/'])]
        app_files = [f for f in all_files if any(f.startswith(p) for p in ['/app/', '/code/', '/src/', '/home/', '/opt/']) and not f.startswith('/usr/')]
        config_files = [f for f in all_files if f.startswith('/etc/')]
        
        # Also categorize accessed files for better analysis
        accessed_system = [f for f in accessed_files if any(f.startswith(p) for p in ['/bin/', '/sbin/', '/lib/', '/usr/', '/lib64/'])]
        accessed_app = [f for f in accessed_files if any(f.startswith(p) for p in ['/app/', '/code/', '/src/', '/home/', '/opt/']) and not f.startswith('/usr/')]
        accessed_config = [f for f in accessed_files if f.startswith('/etc/')]
        
        logger.info(f"File categorization - System: {len(system_files)}, App: {len(app_files)}, Config: {len(config_files)}")
        logger.info(f"Accessed categorization - System: {len(accessed_system)}, App: {len(accessed_app)}, Config: {len(accessed_config)}")
        
        removable_files = sorted(list(set(all_files) - set(accessed_files)))
        removable_system = [f for f in removable_files if f in system_files]
        
        # Enhanced estimation for base images (Ubuntu, Alpine, etc.)
        if len(all_files) < 2000:  # Likely incomplete file list or base image
            logger.info("Limited file discovery or base image detected, estimating removable files")
            
            # For base images, estimate commonly removable files
            estimated_removable = []
            
            # Common removable directories in Ubuntu/Debian
            removable_dirs = [
                '/usr/share/man', '/usr/share/doc', '/usr/share/info', '/usr/share/locale',
                '/usr/share/zoneinfo', '/usr/share/fonts', '/usr/share/icons',
                '/usr/include', '/usr/src', '/var/cache', '/var/log', '/tmp',
                '/usr/share/gcc-*', '/usr/share/perl*', '/usr/share/python*'
            ]
            
            # Check which of these directories exist and add their files
            for dir_path in removable_dirs:
                try:
                    check_result = container.exec_run(f"test -d {dir_path}")
                    if check_result.exit_code == 0:
                        # Add directory and its contents to estimated removable
                        estimated_removable.append(dir_path)
                        # Try to get some files from this directory
                        try:
                            files_result = container.exec_run(f"find {dir_path} -type f 2>/dev/null | head -100")
                            if files_result.exit_code == 0 and files_result.output:
                                files = [f.strip() for f in files_result.output.decode("utf-8", errors="ignore").splitlines() if f.strip()]
                                estimated_removable.extend(files)
                        except Exception:
                            pass
                except Exception:
                    pass
            
            # Add common removable file patterns
            removable_patterns = [
                '*.pyc', '*.pyo', '__pycache__', '*.log', '*.tmp', '*.cache',
                '*.a', '*.la', '*.so.*', '*.o', '*.orig', '*.rej'
            ]
            
            for pattern in removable_patterns:
                try:
                    pattern_result = container.exec_run(f"find /usr -name '{pattern}' 2>/dev/null | head -50")
                    if pattern_result.exit_code == 0 and pattern_result.output:
                        files = [f.strip() for f in pattern_result.output.decode("utf-8", errors="ignore").splitlines() if f.strip()]
                        estimated_removable.extend(files)
                except Exception:
                    pass
            
            if estimated_removable:
                removable_files.extend(estimated_removable)
                removable_system.extend([f for f in estimated_removable if any(f.startswith(p) for p in ['/usr/', '/var/', '/tmp/'])])
                logger.info(f"Added {len(estimated_removable)} estimated removable files for base image")

        # 6️⃣ Calculate sizes
        size_before = "Unknown"
        try:
            exec_size = container.exec_run("du -sh /")
            if exec_size.exit_code == 0:
                size_before = exec_size.output.decode().strip().split()[0]
        except Exception as e:
            logger.warning(f"Could not get container size: {e}")

        # Calculate estimated size reduction
        reduction_percentage = (len(removable_files) / len(all_files) * 100) if all_files else 0
        
        result = {
            "success": True,
            "container_id": container_id,
            "os_info": os_info,
            "analysis": {
                "total_files": len(all_files),
                "accessed_files": len(accessed_files),
                "removable_files": len(removable_files),
                "system_files": len(system_files),
                "app_files": len(app_files),
                "config_files": len(config_files),
                "removable_system_files": len(removable_system),
            },
            "file_samples": {
                "accessed_files": accessed_files[:20],
                "removable_files": removable_files[:50],
                "removable_system": removable_system[:30],
            },
            "size_info": {
                "current_size": size_before,
                "estimated_reduction": f"{reduction_percentage:.1f}%"
            }
        }
        
        logger.info(f"Analysis completed successfully: {len(all_files)} total files, {len(accessed_files)} accessed, {len(removable_files)} removable")
        return jsonify(result)

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500
    finally:
        # Always cleanup container
        if container:
            try:
                container.remove(force=True)
                logger.info(f"Cleaned up container: {container_id}")
            except Exception as e:
                logger.warning(f"Failed to cleanup container: {e}")

@app.route("/recommendations", methods=["POST"])
def get_recommendations():
    """Provide detailed optimization recommendations based on analysis"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No analysis data provided"}), 400
    
    analysis = data.get("analysis", {})
    accessed_files = data.get("file_samples", {}).get("accessed_files", [])
    
    recommendations = []
    
    # Analyze Python dependencies
    python_libs = [f for f in accessed_files if '/python3.' in f and '/lib/' in f]
    venv_files = [f for f in accessed_files if '/venv/' in f or '/site-packages/' in f]
    
    if python_libs:
        recommendations.append({
            "category": "Python Optimization",
            "title": "Use Python Slim Base Image",
            "description": f"Detected {len(python_libs)} Python library files. Consider using python:3.12-slim or python:3.12-alpine base image.",
            "impact": "High",
            "estimated_savings": "50-70%",
            "implementation": "Change FROM python:3.12 to FROM python:3.12-slim in Dockerfile"
        })
    
    if venv_files:
        recommendations.append({
            "category": "Dependencies",
            "title": "Optimize Virtual Environment",
            "description": f"Found {len(venv_files)} virtual environment files. Remove development dependencies in production.",
            "impact": "Medium",
            "estimated_savings": "20-30%",
            "implementation": "Use pip install --no-dev or requirements-prod.txt"
        })
    
    # Check for common removable files
    cache_files = [f for f in accessed_files if any(x in f for x in ['cache', '__pycache__', '.pyc'])]
    if cache_files:
        recommendations.append({
            "category": "Cache Cleanup",
            "title": "Remove Cache Files",
            "description": f"Found {len(cache_files)} cache files that can be removed.",
            "impact": "Low",
            "estimated_savings": "5-10%",
            "implementation": "Add RUN find / -name '*.pyc' -delete && find / -name '__pycache__' -type d -exec rm -rf {} +"
        })
    
    # Generate summary
    summary = {
        "total_recommendations": len(recommendations),
        "high_impact": len([r for r in recommendations if r["impact"] == "High"]),
        "potential_savings": "50-80%" if recommendations else "Unknown"
    }
    
    return jsonify({
        "success": True,
        "recommendations": recommendations,
        "summary": summary
    })

def _humanize_bytes(bytes_value):
    """Convert bytes to human readable format"""
    if bytes_value == "Unknown":
        return "Unknown"
    try:
        bytes_value = int(bytes_value)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f}{unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f}TB"
    except (ValueError, TypeError):
        return "Unknown"

def _get_container_fs_size_bytes(container):
    """Get container filesystem size in bytes"""
    try:
        result = container.exec_run("du -sb /")
        if result.exit_code == 0:
            size_bytes = int(result.output.decode().strip().split()[0])
            return size_bytes, _humanize_bytes(size_bytes)
    except Exception as e:
        logger.warning(f"Failed to get container FS size: {e}")
    return "Unknown", "Unknown"

def _get_image_size_bytes(image_uri):
    """Get Docker image size in bytes"""
    try:
        image = client.images.get(image_uri)
        size_bytes = image.attrs['Size']
        return size_bytes, _humanize_bytes(size_bytes)
    except Exception as e:
        logger.warning(f"Failed to get image size for {image_uri}: {e}")
    return "Unknown", "Unknown"

@app.route("/slim", methods=["POST"])
def slim_and_push():
    """
    Remove unwanted files from container and push slimmed image to ECR
    """
    if not client:
        return jsonify({"error": "Docker client not available"}), 500
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    image = data.get("image")
    removable_files = data.get("removable_files", [])
    
    if not image:
        return jsonify({"error": "No image provided"}), 400
    
    if not removable_files:
        return jsonify({"error": "No removable files provided"}), 400
    
    logger.info(f"[slim] Starting slimming process for {image}")
    logger.info(f"[slim] Will remove {len(removable_files)} files")
    
    container = None
    deletion_results = []
    
    # Get initial image size
    image_size_before = _get_image_size_bytes(image)

    try:
        # Ensure image is present
        logger.info(f"[slim] pulling image: {image}")
        client.images.pull(image)

        # Start container
        logger.info("[slim] starting container for slimming")
        container = client.containers.run(image, command="/bin/sh", detach=True, tty=True, remove=False)

        # Measure size before (inside container)
        size_before = _get_container_fs_size_bytes(container)
        logger.info(f"[slim] container FS size before: {size_before} bytes ({_humanize_bytes(size_before)})")

        # Remove files (best-effort)
        if removable_files:
            # Build a safe shell to rm -rf each file; ignore errors
            for path in removable_files:
                if not path or ".." in path:
                    deletion_results.append({"path": path, "status": "skipped"})
                    continue
                try:
                    cmd = "sh -lc 'rm -rf -- " + path.replace("'", "'\\''") + "'"
                    logger.info(f"[slim] deleting: {path} via {cmd}")
                    res = container.exec_run(cmd, demux=True)
                    stdout, stderr = res.output if isinstance(res.output, tuple) else (res.output, None)
                    out = (stdout or b"").decode(errors='ignore')
                    err = (stderr or b"").decode(errors='ignore') if stderr else ""
                    logger.info(f"[slim] delete rc={res.exit_code} out='{out.strip()}' err='{err.strip()}'")
                    deletion_results.append({
                        "path": path,
                        "exit_code": res.exit_code,
                        "status": "removed" if res.exit_code == 0 else "failed"
                    })
                except Exception as e:
                    deletion_results.append({"path": path, "status": "error", "error": str(e)})

        # Measure size after (inside container)
        size_after = _get_container_fs_size_bytes(container)
        logger.info(f"[slim] container FS size after: {size_after} bytes ({_humanize_bytes(size_after)})")

        # Commit container to new image
        repo_uri_base = "/".join(image.split('/')[:-1]) if '/' in image else image.split(':')[0]
        new_tag = f"slim-{int(time.time())}"
        new_image_uri = f"{repo_uri_base}:{new_tag}"
        
        logger.info(f"[slim] committing container to {repo_uri_base}:{new_tag}")
        committed = client.api.commit(container=container.id, repository=repo_uri_base, tag=new_tag)

        # ECR login via auth token
        try:
            ecr = boto3.client('ecr',
                               aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                               aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
                               region_name=os.getenv('AWS_DEFAULT_REGION', 'ap-south-1'))
            auth = ecr.get_authorization_token()
            auth_data = auth['authorizationData'][0]
            proxy_endpoint = auth_data['proxyEndpoint']  # e.g., https://xxxxxxxx.dkr.ecr.region.amazonaws.com
            import base64
            username, password = base64.b64decode(auth_data['authorizationToken']).decode().split(':')
            login_registry = proxy_endpoint.replace('https://','')
            logger.info(f"[slim] docker login registry={login_registry}")
            client.login(username=username, password=password, registry=login_registry)
        except Exception as e:
            logger.warning(f"ECR login failed: {e}")

        # Push the image
        logger.info(f"[slim] pushing image {repo_uri_base}:{new_tag}")
        push_logs = client.images.push(repo_uri_base, tag=new_tag, stream=False)
        logger.info(f"[slim] push result: {push_logs}")

        # Also compute image size after push (locally)
        image_size_after = _get_image_size_bytes(f"{repo_uri_base}:{new_tag}")

        logger.info(f"[slim] image sizes: before={image_size_before} after={image_size_after}")

        response = {
            "success": True,
            "source_image": image,
            "new_image": new_image_uri,
            "before_after": {
                "size_before_bytes": size_before,
                "size_after_bytes": size_after,
                "size_before": _humanize_bytes(size_before),
                "size_after": _humanize_bytes(size_after),
                "image_size_before_bytes": image_size_before,
                "image_size_after_bytes": image_size_after,
                "image_size_before": _humanize_bytes(image_size_before),
                "image_size_after": _humanize_bytes(image_size_after)
            },
            "removed_files": len([r for r in deletion_results if r.get("status") == "removed"]),
            "deletion_results": deletion_results,
            "push_result": push_logs
        }
        return jsonify(response)

    except Exception as e:
        logger.error(f"Slim and push failed: {e}")
        return jsonify({"error": f"Slim and push failed: {str(e)}"}), 500
    finally:
        if container:
            safe_remove_container(container)

def analyze_without_strace(container, container_id):
    """Enhanced fallback analysis method when strace is not available - optimized for base images"""
    try:
        logger.info("Using enhanced fallback analysis method without strace")
        
        # Get all files with comprehensive discovery
        logger.info("Getting comprehensive file list from container...")
        
        # Try multiple file discovery approaches
        find_commands = [
            "find / -type f -not -path '/dev/*' -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -10000",
            "find /usr /bin /sbin /lib /lib64 /etc /opt -type f 2>/dev/null | head -8000",
            "find /usr -type f 2>/dev/null | head -5000"
        ]
        
        all_files = []
        for i, cmd in enumerate(find_commands):
            logger.info(f"Fallback file discovery method {i+1}: {cmd}")
            try:
                exec_ls = container.exec_run(cmd)
                logger.info(f"Fallback method {i+1} exit code: {exec_ls.exit_code}")
                
                if exec_ls.exit_code == 0 and exec_ls.output:
                    files = [f.strip() for f in exec_ls.output.decode("utf-8", errors="ignore").splitlines() if f.strip()]
                    if files:
                        all_files = files
                        logger.info(f"Found {len(all_files)} files using fallback method {i+1}")
                        break
            except Exception as e:
                logger.warning(f"Fallback method {i+1} failed: {e}")
                continue
        
        if not all_files:
            logger.warning("All fallback file discovery methods failed, using basic directory listing")
            # Try basic directory listing
            basic_dirs = ['/usr', '/bin', '/sbin', '/lib', '/etc']
            for dir_path in basic_dirs:
                try:
                    exec_ls = container.exec_run(f"find {dir_path} -type f 2>/dev/null | head -500")
                    if exec_ls.exit_code == 0 and exec_ls.output:
                        files = [f.strip() for f in exec_ls.output.decode("utf-8", errors="ignore").splitlines() if f.strip()]
                        all_files.extend(files)
                except Exception as e:
                    logger.warning(f"Failed to list {dir_path}: {e}")
                    continue

        # Categorize files with improved logic
        system_files = [f for f in all_files if any(f.startswith(p) for p in ['/bin/', '/sbin/', '/lib/', '/usr/', '/lib64/'])]
        app_files = [f for f in all_files if any(f.startswith(p) for p in ['/app/', '/code/', '/src/', '/home/', '/opt/']) and not f.startswith('/usr/')]
        config_files = [f for f in all_files if f.startswith('/etc/')]
        
        # For base images without strace, estimate removable files more aggressively
        logger.info("Estimating removable files for base image without strace data")
        
        # Common removable directories and files in Ubuntu/Debian base images
        removable_dirs = [
            '/usr/share/man', '/usr/share/doc', '/usr/share/info', '/usr/share/locale',
            '/usr/share/zoneinfo', '/usr/share/fonts', '/usr/share/icons',
            '/usr/include', '/usr/src', '/var/cache', '/var/log', '/tmp',
            '/usr/share/gcc-*', '/usr/share/perl*', '/usr/share/python*',
            '/usr/share/bash-completion', '/usr/share/misc'
        ]
        
        potentially_removable = []
        
        # Check which directories exist and estimate their files
        for dir_path in removable_dirs:
            try:
                check_result = container.exec_run(f"test -d {dir_path}")
                if check_result.exit_code == 0:
                    potentially_removable.append(dir_path)
                    # Try to get some files from this directory
                    try:
                        files_result = container.exec_run(f"find {dir_path} -type f 2>/dev/null | head -200")
                        if files_result.exit_code == 0 and files_result.output:
                            files = [f.strip() for f in files_result.output.decode("utf-8", errors="ignore").splitlines() if f.strip()]
                            potentially_removable.extend(files)
                    except Exception:
                        pass
            except Exception:
                pass
        
        # Add common removable file patterns
        removable_patterns = [
            '*.pyc', '*.pyo', '__pycache__', '*.log', '*.tmp', '*.cache',
            '*.a', '*.la', '*.so.*', '*.o', '*.orig', '*.rej', '*.bak'
        ]
        
        for pattern in removable_patterns:
            try:
                pattern_result = container.exec_run(f"find /usr -name '{pattern}' 2>/dev/null | head -100")
                if pattern_result.exit_code == 0 and pattern_result.output:
                    files = [f.strip() for f in pattern_result.output.decode("utf-8", errors="ignore").splitlines() if f.strip()]
                    potentially_removable.extend(files)
            except Exception:
                pass

        # Get size info
        size_before = "Unknown"
        try:
            logger.info("Getting container size...")
            exec_size = container.exec_run("du -sh /")
            if exec_size.exit_code == 0:
                size_output = exec_size.output.decode().strip()
                size_before = size_output.split()[0] if size_output else "Unknown"
                logger.info(f"Container size: {size_before}")
        except Exception as e:
            logger.warning(f"Could not get container size: {e}")

        # Calculate estimated size reduction
        total_estimated_removable = len(potentially_removable)
        reduction_percentage = (total_estimated_removable / len(all_files) * 100) if all_files else 0
        
        logger.info(f"Fallback analysis complete - Total files: {len(all_files)}, Estimated removable: {total_estimated_removable}")

        result = {
            "success": True,
            "container_id": container_id,
            "note": "Analysis completed using enhanced fallback method (strace not available) - optimized for base images",
            "analysis": {
                "total_files": len(all_files),
                "accessed_files": 0,  # No strace data available
                "removable_files": total_estimated_removable,
                "potentially_removable": total_estimated_removable,
                "system_files": len(system_files),
                "app_files": len(app_files),
                "config_files": len(config_files),
                "removable_system_files": len([f for f in potentially_removable if any(f.startswith(p) for p in ['/usr/', '/var/', '/tmp/'])]),
            },
            "file_samples": {
                "accessed_files": [],
                "removable_files": potentially_removable[:50],  # Show first 50
                "removable_system": [f for f in potentially_removable if any(f.startswith(p) for p in ['/usr/', '/var/', '/tmp/'])][:30],
            },
            "size_info": {
                "current_size": size_before,
                "estimated_reduction": f"{reduction_percentage:.1f}%"
            }
        }
        
        logger.info(f"Enhanced fallback analysis completed successfully: {len(all_files)} total files, {total_estimated_removable} potentially removable")
        return jsonify(result)
            
    except Exception as e:
        logger.error(f"Enhanced fallback analysis failed: {e}")
        return jsonify({"error": f"Enhanced fallback analysis failed: {str(e)}"}), 500
    
    finally:
        # Always cleanup container
        safe_remove_container(container)

def _humanize_size_str(size_str):
    try:
        # already human
        return size_str
    except Exception:
        return "Unknown"

def _categorize_path(path):
    if path.startswith('/etc/'):
        return 'config'
    if path.startswith('/bin/') or path.startswith('/sbin/'):
        return 'system'
    if path.startswith('/usr/bin/') or path.startswith('/usr/sbin/') or path.startswith('/usr/lib/') or path.startswith('/lib/') or path.startswith('/lib64/'):
        return 'system'
    if path.startswith('/var/www/') or path.startswith('/app/') or path.startswith('/opt/') or path.startswith('/srv/') or path.startswith('/home/') or path.startswith('/workdir/'):
        return 'application'
    return 'other'

def _removal_reason(path, accessed):
    if accessed:
        return None
    # docs/man/locales
    if any(x in path for x in ['/usr/share/man/', '/usr/share/doc/', '/usr/share/info/', '/usr/share/locale/']):
        return 'documentation not used at runtime'
    # caches/logs/tmp
    if any(x in path for x in ['/var/cache/', '/var/log/', '/tmp/']):
        return 'cache/log/temp data, safe to remove'
    # headers/sources
    if any(x in path for x in ['/usr/include/', '/usr/src/']):
        return 'development headers/sources'
    # python/node build artifacts
    if any(x in path for x in ['__pycache__', '.pyc', '.pyo', '.cache']):
        return 'bytecode/cache not needed at runtime'
    if any(x in path for x in ['/test/', '/tests/', '/examples/']):
        return 'tests/examples not needed at runtime'
    return 'not accessed during runtime'

def _keep_reason(path, accessed):
    if accessed:
        return 'needed at runtime (accessed)'
    if path.startswith('/lib/') or path.startswith('/lib64/') or '/lib/' in path:
        return 'system library dependency'
    if path.startswith('/bin/') or path.startswith('/usr/bin/') or path.startswith('/sbin/'):
        return 'part of base system/commands'
    if path.startswith('/etc/'):
        return 'configuration file'
    if any(path.startswith(p) for p in ['/app/', '/opt/', '/srv/', '/var/www/']):
        return 'application artifact (not traced but likely needed)'
    return 'retained by policy'

def analyze_container_image(image: str, trace_duration: int = 10) -> Dict[str, Any]:
    """Universal image analysis returning the requested JSON schema."""
    if not client:
        raise RuntimeError('Docker client not available')

    container = None
    accessed_files: List[str] = []
    try:
        client.images.pull(image)
        container = client.containers.run(image, command="/bin/sh", detach=True, tty=True, remove=False)
        container_id = container.id[:12]

        # Processes
        running_processes = []
        try:
            ps = container.exec_run('ps aux')
            if ps.exit_code == 0 and ps.output:
                for line in ps.output.decode('utf-8', errors='ignore').splitlines()[1:]:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        running_processes.append({"pid": int(parts[1]) if parts[1].isdigit() else parts[1], "cmd": parts[10]})
        except Exception:
            pass

        # Try to enable strace
        def _ensure_strace():
            chk = container.exec_run('which strace')
            if chk.exit_code == 0:
                return True
            # try apt
            if container.exec_run('which apt').exit_code == 0:
                container.exec_run('sh -lc "apt-get update && apt-get install -y strace"', user='root')
            elif container.exec_run('which apk').exit_code == 0:
                container.exec_run('sh -lc "apk add --no-cache strace"', user='root')
            elif container.exec_run('which yum').exit_code == 0:
                container.exec_run('sh -lc "yum install -y strace || true"', user='root')
            elif container.exec_run('which dnf').exit_code == 0:
                container.exec_run('sh -lc "dnf install -y strace || true"', user='root')
            return container.exec_run('which strace').exit_code == 0

        used_strace = False
        try:
            if _ensure_strace():
                log_path = f"/tmp/strace_{int(time.time())}.log"
                # attach to pid 1 for a short window
                container.exec_run(f"sh -lc 'strace -f -e trace=file -o {log_path} -p 1 & sleep {trace_duration}; kill %1 2>/dev/null || true'", detach=False)
                # read log
                try:
                    bits, _ = container.get_archive(log_path)
                    file_like = io.BytesIO(b"".join(chunk for chunk in bits))
                    with tarfile.open(fileobj=file_like) as tar:
                        member = tar.getmembers()[0]
                        extracted = tar.extractfile(member)
                        content = extracted.read().decode('utf-8', errors='ignore') if extracted else ''
                    for line in content.splitlines():
                        if any(tok in line for tok in ['open(', 'openat(', 'stat(']):
                            parts = line.split('"')
                            if len(parts) > 1:
                                p = parts[1]
                                if p.startswith('/') and not any(skip in p for skip in ['/proc/', '/sys/', '/dev/']):
                                    accessed_files.append(p)
                    used_strace = True
                except Exception:
                    used_strace = False
        except Exception:
            used_strace = False

        accessed_set = set(accessed_files)

        # File discovery (robust)
        file_paths: List[str] = []
        find_cmds = [
            "find / -xdev -type f -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' 2>/dev/null | head -20000",
            "find /usr /bin /sbin /lib /lib64 /etc /opt /var -type f 2>/dev/null | head -15000",
            "find / -type f 2>/dev/null | head -30000"
        ]
        for cmd in find_cmds:
            try:
                res = container.exec_run(cmd)
                if res.exit_code == 0 and res.output:
                    file_paths = [p.strip() for p in res.output.decode('utf-8', errors='ignore').splitlines() if p.strip()]
                    if file_paths:
                        break
            except Exception:
                continue
        if not file_paths:
            try:
                res = container.exec_run("sh -lc \"find / -xdev -type f -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' 2>/dev/null\"")
                if res.exit_code == 0 and res.output:
                    file_paths = [p.strip() for p in res.output.decode('utf-8', errors='ignore').splitlines() if p.strip()]
            except Exception:
                pass
        if not file_paths:
            try:
                res = container.exec_run("sh -lc 'ls -lRa / 2>/dev/null | awk \"$1 ~ /^[^-]/ {next} {print \\ $9}\"'")
                if res.exit_code == 0 and res.output:
                    candidates = [p.strip() for p in res.output.decode('utf-8', errors='ignore').splitlines() if p.strip()]
                    file_paths = [p for p in candidates if p.startswith('/')]
            except Exception:
                pass
        if not file_paths:
            file_paths = list(accessed_set)

        # Categories & reasons
        removable_files_with_reasons = []
        kept_files_with_reasons = []
        unused_files = []
        system_count = config_count = app_count = 0
        for p in file_paths:
            cat = _categorize_path(p)
            if cat == 'system':
                system_count += 1
            elif cat == 'config':
                config_count += 1
            elif cat == 'application':
                app_count += 1
            acc = p in accessed_set
            reason = _removal_reason(p, acc)
            if not acc and reason:
                removable_files_with_reasons.append({"file": p, "reason": reason})
                unused_files.append(p)
            else:
                kept_files_with_reasons.append({"file": p, "reason": _keep_reason(p, acc)})

        # Sizes
        total_size = "Unknown"
        try:
            du = container.exec_run("du -sh /")
            if du.exit_code == 0 and du.output:
                total_size = du.output.decode().strip().split()[0]
        except Exception:
            pass

        estimated_reduction = "0%"
        if file_paths:
            pct = (len(unused_files) / len(file_paths)) * 100
            estimated_reduction = f"{pct:.0f}%"

        return {
            "total_files": len(file_paths),
            "total_size": _humanize_size_str(total_size),
            "accessed_files": sorted(list(accessed_set))[:2000],
            "unused_files": unused_files[:2000],
            "removable_files_with_reasons": removable_files_with_reasons[:2000],
            "kept_files_with_reasons": kept_files_with_reasons[:2000],
            "running_processes": running_processes[:200],
            "estimated_reduction": estimated_reduction,
            "breakdown": {
                "system": system_count,
                "config": config_count,
                "application": app_count
            },
            "metadata": {
                "image": image,
                "container_id": container_id,
                "used_strace": used_strace
            }
        }

    finally:
        if container:
            safe_remove_container(container)

@app.route("/analyze/schema", methods=["POST"])
def analyze_schema():
    data = request.get_json() or {}
    image = data.get("image")
    if not image:
        return jsonify({"error": "No image provided"}), 400
    try:
        result = analyze_container_image(image)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Schema analysis failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/analyze/full", methods=["POST"])
def analyze_full():
    data = request.get_json() or {}
    image = data.get("image")
    if not image:
        return jsonify({"error": "No image provided"}), 400
    try:
        analyzer = ImageAnalyzer()
        base = analyzer.analyze(image)
        # add or refine suggestions
        base["optimization_suggestions"] = generate_slimming_recommendations(base)
        return jsonify(base)
    except Exception as e:
        logger.error(f"Full analysis failed: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
