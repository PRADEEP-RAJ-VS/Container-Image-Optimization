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
            remove=False  # Don't auto-remove so we can clean up manually
        )
        container_id = container.id[:12]
        logger.info(f"Started container: {container_id}")

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

        # 2️⃣ Run strace inside container - trace actual application like old.py
        # First check if app.py exists, if not try other common Python files
        app_check = container.exec_run("find /app -name '*.py' | head -1")
        app_file = None
        
        if app_check.exit_code == 0 and app_check.output:
            found_app = app_check.output.decode().strip()
            if found_app:
                app_file = found_app
                logger.info(f"Found Python app: {app_file}")
        
        # If no app found in /app, try common locations
        if not app_file:
            for possible_app in ["/app/app.py", "/app/main.py", "/usr/src/app/app.py", "/code/app.py"]:
                check_result = container.exec_run(f"test -f {possible_app}")
                if check_result.exit_code == 0:
                    app_file = possible_app
                    logger.info(f"Found Python app at: {app_file}")
                    break
        
        # If still no app found, try to run a simple Python command to trace Python libraries
        if not app_file:
            logger.info("No Python app found, tracing Python import system instead")
            strace_cmd = f"strace -f -e trace=file -o {log_path} python -c 'import sys; import os; print(\"Python tracing complete\")'"
        else:
            # Run strace with the actual application like old.py does
            strace_cmd = f"strace -f -e trace=file -o {log_path} python {app_file}"
        
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

        # 5️⃣ List all files in container with better filtering and timeout
        logger.info("Starting file discovery...")
        all_files = []
        
        # Try multiple approaches for file discovery
        find_commands = [
            "find / -type f -not -path '/dev/*' -not -path '/proc/*' -not -path '/sys/*' -not -path '/tmp/*' 2>/dev/null | head -10000",
            "find /usr /app /bin /sbin /lib /etc -type f 2>/dev/null | head -10000",
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
            logger.warning("All file discovery methods failed, using accessed files as reference")
            # Use accessed files to estimate total files
            all_files = list(accessed_files)

        # Calculate file categories with improved logic
        system_files = [f for f in all_files if any(f.startswith(p) for p in ['/bin/', '/sbin/', '/lib/', '/usr/'])]
        app_files = [f for f in all_files if any(f.startswith(p) for p in ['/app/', '/code/', '/src/', '/home/']) and not f.startswith('/usr/')]
        config_files = [f for f in all_files if f.startswith('/etc/')]
        
        # Also categorize accessed files for better analysis
        accessed_system = [f for f in accessed_files if any(f.startswith(p) for p in ['/bin/', '/sbin/', '/lib/', '/usr/'])]
        accessed_app = [f for f in accessed_files if any(f.startswith(p) for p in ['/app/', '/code/', '/src/', '/home/']) and not f.startswith('/usr/')]
        accessed_config = [f for f in accessed_files if f.startswith('/etc/')]
        
        logger.info(f"File categorization - System: {len(system_files)}, App: {len(app_files)}, Config: {len(config_files)}")
        logger.info(f"Accessed categorization - System: {len(accessed_system)}, App: {len(accessed_app)}, Config: {len(accessed_config)}")
        
        removable_files = sorted(list(set(all_files) - set(accessed_files)))
        removable_system = [f for f in removable_files if f in system_files]
        
        # If we have limited file discovery, estimate removable files based on accessed patterns
        if len(all_files) < 1000:  # Likely incomplete file list
            logger.info("Limited file discovery, estimating removable files from accessed patterns")
            
            # Identify potentially unused system components based on accessed files
            unused_patterns = []
            
            # Check for unused Python packages in accessed files
            python_packages = set()
            for f in accessed_files:
                if '/site-packages/' in f or '/dist-packages/' in f:
                    parts = f.split('/')
                    for i, part in enumerate(parts):
                        if part in ['site-packages', 'dist-packages'] and i + 1 < len(parts):
                            python_packages.add(parts[i + 1])
            
            # Estimate total Python packages (common ones that might not be used)
            common_unused_packages = [
                'pip', 'setuptools', 'wheel', 'distutils', 'pkg_resources',
                'test', 'tests', 'unittest', 'doctest', 'pydoc'
            ]
            
            # Create estimated removable files
            estimated_removable = []
            for pkg in common_unused_packages:
                if pkg not in python_packages:
                    estimated_removable.extend([
                        f'/usr/local/lib/python3.12/site-packages/{pkg}',
                        f'/usr/local/lib/python3.12/{pkg}'
                    ])
            
            # Add common removable system files
            estimated_removable.extend([
                '/usr/share/man', '/usr/share/doc', '/usr/share/info',
                '/usr/include', '/usr/src', '/var/cache', '/tmp'
            ])
            
            if estimated_removable:
                removable_files.extend(estimated_removable)
                removable_system.extend([f for f in estimated_removable if any(f.startswith(p) for p in ['/usr/', '/var/'])])
                logger.info(f"Added {len(estimated_removable)} estimated removable files")

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
            "analysis": {
                "total_files": len(all_files),
                "accessed_files": len(accessed_files),
                "removable_files": len(removable_files),
                "system_files": len(system_files),
                "removable_system_files": len(removable_system),
                "app_files": len(app_files),
                "config_files": len(config_files)
            },
            "size_info": {
                "current_size": size_before,
                "estimated_reduction": f"{reduction_percentage:.1f}%"
            },
            "file_samples": {
                "accessed_files": accessed_files[:20],
                "removable_files": removable_files[:20],
                "removable_system": removable_system[:20]
            }
        }

        return jsonify(result)
            
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500
    
    finally:
        # Always cleanup container
        if container:
            try:
                container.remove(force=True)
                logger.info(f"Cleaned up container: {container.id[:12]}")
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
            "title": "Remove Python Cache Files",
            "description": f"Found {len(cache_files)} cache files that can be safely removed.",
            "impact": "Low",
            "estimated_savings": "5-10%",
            "implementation": "Add RUN find . -name '*.pyc' -delete && find . -name '__pycache__' -delete to Dockerfile"
        })
    
    # Multi-stage build recommendation
    recommendations.append({
        "category": "Build Strategy",
        "title": "Implement Multi-stage Build",
        "description": "Use multi-stage Docker builds to separate build dependencies from runtime.",
        "impact": "High",
        "estimated_savings": "40-60%",
        "implementation": "Create separate build and runtime stages in Dockerfile"
    })
    
    # Distroless recommendation
    recommendations.append({
        "category": "Base Image",
        "title": "Consider Distroless Images",
        "description": "Use Google's distroless images for maximum security and minimal size.",
        "impact": "Very High",
        "estimated_savings": "70-80%",
        "implementation": "Use gcr.io/distroless/python3 as base image"
    })
    
    return jsonify({
        "recommendations": recommendations,
        "summary": {
            "total_recommendations": len(recommendations),
            "high_impact": len([r for r in recommendations if r["impact"] == "High"]),
            "potential_savings": "40-80%"
        }
    })

@app.route("/slim", methods=["POST"])
def slim_and_push():
    """Remove unwanted files, commit container, tag and push to ECR with a new tag.
    Expected JSON body: { image: str, removable_files: [str], new_tag?: str }
    """
    if not client:
        return jsonify({"error": "Docker client not available"}), 500

    data = request.get_json(force=True, silent=True) or {}
    image = (data.get("image") or "").strip()
    removable_files = data.get("removable_files") or []
    requested_tag = (data.get("new_tag") or "").strip()

    if not image:
        return jsonify({"error": "Image is required"}), 400

    # Derive registry/repo:tag
    try:
        registry_and_path, tag = image.rsplit(":", 1)
    except ValueError:
        registry_and_path, tag = image, "latest"

    try:
        registry, repository = registry_and_path.split("/", 1)
    except ValueError:
        return jsonify({"error": "Image must be a fully qualified ECR URI"}), 400

    # Determine new tag
    timestamp_tag = str(int(time.time()))
    new_tag = requested_tag or f"slim-{timestamp_tag}"
    new_image_uri = f"{registry_and_path}:{new_tag}"

    container = None
    deletion_results = []
    size_before = "Unknown"
    size_after = "Unknown"

    try:
        # Ensure image is present
        client.images.pull(image)

        # Start container
        container = client.containers.run(image, command="/bin/sh", detach=True, tty=True, remove=False)

        # Measure size before (inside container)
        try:
            s_before = container.exec_run("du -sb / 2>/dev/null | awk '{print $1}'")
            if s_before.exit_code == 0 and s_before.output:
                size_before = s_before.output.decode().strip()
        except Exception:
            pass

        # Remove files (best-effort)
        if removable_files:
            # Build a safe shell to rm -rf each file; ignore errors
            for path in removable_files:
                if not path or ".." in path:
                    deletion_results.append({"path": path, "status": "skipped"})
                    continue
                try:
                    res = container.exec_run(f"sh -lc 'rm -rf -- " + path.replace("'", "'\\''") + "'" )
                    deletion_results.append({
                        "path": path,
                        "exit_code": res.exit_code,
                        "status": "removed" if res.exit_code == 0 else "failed"
                    })
                except Exception as e:
                    deletion_results.append({"path": path, "status": "error", "error": str(e)})

        # Measure size after (inside container)
        try:
            s_after = container.exec_run("du -sb / 2>/dev/null | awk '{print $1}'")
            if s_after.exit_code == 0 and s_after.output:
                size_after = s_after.output.decode().strip()
        except Exception:
            pass

        # Commit container to new image
        committed = client.api.commit(container=container.id, repository=registry_and_path, tag=new_tag)

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
            client.login(username=username, password=password, registry=proxy_endpoint.replace('https://',''))
        except Exception as e:
            logger.warning(f"ECR login failed: {e}")

        # Push the image
        push_logs = client.images.push(registry_and_path, tag=new_tag, stream=False)

        # Compute human readable sizes if bytes
        def humanize(bytes_str: str) -> str:
            try:
                b = int(bytes_str)
                for unit in ['B','KB','MB','GB','TB']:
                    if b < 1024:
                        return f"{b:.1f}{unit}" if unit != 'B' else f"{b}B"
                    b /= 1024
            except Exception:
                return bytes_str or "Unknown"
            return bytes_str

        response = {
            "success": True,
            "source_image": image,
            "new_image": new_image_uri,
            "before_after": {
                "size_before_bytes": size_before,
                "size_after_bytes": size_after,
                "size_before": humanize(size_before),
                "size_after": humanize(size_after)
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
            try:
                container.remove(force=True)
            except Exception:
                pass

def analyze_without_strace(container, container_id):
    """Fallback analysis method when strace is not available"""
    try:
        logger.info("Using fallback analysis method without strace")
        
        # Get all files with better error handling
        logger.info("Getting file list from container...")
        exec_ls = container.exec_run("find / -type f -not -path '/dev/*' -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null")
        logger.info(f"File listing command exit code: {exec_ls.exit_code}")
        
        all_files = []
        if exec_ls.exit_code == 0:
            all_files = [f.strip() for f in exec_ls.output.decode("utf-8", errors="ignore").splitlines() if f.strip()]
            logger.info(f"Found {len(all_files)} files in container")
        else:
            logger.warning("File listing command failed, trying simpler approach")
            # Try simpler command
            exec_ls_simple = container.exec_run("ls -la /")
            if exec_ls_simple.exit_code == 0:
                logger.info("Simple ls command worked, but limited file discovery")

        # Categorize files
        system_files = [f for f in all_files if any(f.startswith(p) for p in ['/bin/', '/sbin/', '/lib/', '/usr/'])]
        app_files = [f for f in all_files if not any(f.startswith(p) for p in ['/bin/', '/sbin/', '/lib/', '/usr/', '/var/', '/etc/'])]
        config_files = [f for f in all_files if f.startswith('/etc/')]
        
        # Estimate commonly unused system files
        potentially_removable = [f for f in system_files if any(pattern in f for pattern in [
            'man/', 'doc/', 'info/', 'locale/', 'share/doc', 'include/', 'src/', 'cache/'
        ])]

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

        # Calculate reduction percentage
        reduction_pct = (len(potentially_removable) / len(all_files) * 100) if all_files else 0

        result = {
            "success": True,
            "container_id": container_id,
            "note": "Analysis performed without runtime tracing - showing estimated removable files",
            "analysis": {
                "total_files": len(all_files),
                "system_files": len(system_files),
                "app_files": len(app_files),
                "config_files": len(config_files),
                "potentially_removable": len(potentially_removable),
                "accessed_files": 0,  # Not available without strace
                "removable_files": len(potentially_removable)
            },
            "size_info": {
                "current_size": size_before,
                "estimated_reduction": f"{reduction_pct:.1f}%"
            },
            "file_samples": {
                "system_files": system_files[:20],
                "app_files": app_files[:20],
                "potentially_removable": potentially_removable[:20],
                "accessed_files": [],  # Not available without strace
                "removable_files": potentially_removable[:20]
            }
        }
        
        logger.info(f"Fallback analysis completed successfully: {len(all_files)} total files, {len(potentially_removable)} potentially removable")
        return jsonify(result)
            
    except Exception as e:
        logger.error(f"Fallback analysis failed: {e}")
        return jsonify({"error": f"Fallback analysis failed: {str(e)}"}), 500
    
    finally:
        # Always cleanup container
        try:
            container.remove(force=True)
            logger.info(f"Cleaned up container in fallback: {container_id}")
        except Exception as e:
            logger.warning(f"Failed to cleanup container in fallback: {e}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
