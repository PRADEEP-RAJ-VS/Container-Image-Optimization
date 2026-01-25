# 🚀 Docker Optimizer - AWS ECR & ECS Integration

Complete Docker image optimization tool with AWS ECR and ECS integration.

## Features

- ✅ **Docker Image Analysis** - Analyze images from local files or Docker Hub
- ✅ **Security Scanning** - Real Trivy vulnerability scanning
- ✅ **Image Optimization** - Reduce image sizes by 30-70%
- ✅ **AWS ECR Integration** - Push original and optimized images to ECR
- ✅ **AWS ECS Deployment** - One-click deployment to ECS Fargate
- ✅ **Runtime Optimization** - Continuous cleanup during container execution

## Prerequisites

1. **Docker Desktop** - Running and accessible
2. **Trivy Scanner** - Installed (for real vulnerability scans)
3. **AWS CLI** - Configured with credentials
4. **Node.js 18+** and **pnpm**

## Quick Start

### 1. Install Dependencies

```bash
pnpm install
```

### 2. Configure AWS Credentials

Copy `.env.example` to `.env.local`:

```bash
cp .env.example .env.local
```

Edit `.env.local` with your AWS credentials:

```env
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
```

### 3. Run Development Server

```bash
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000)

## AWS Setup

### ECR Setup

Create an ECR repository (or let the app create it automatically):

```bash
aws ecr create-repository --repository-name docker-optimizer --region us-east-1
```

### ECS Setup

1. **Create an ECS Cluster**:

```bash
aws ecs create-cluster --cluster-name docker-optimizer-cluster --region us-east-1
```

2. **Create IAM Role** (required for ECS tasks):

```bash
aws iam create-role --role-name ecsTaskExecutionRole \
  --assume-role-policy-document file://ecs-trust-policy.json
```

3. **Attach Policy**:

```bash
aws iam attach-role-policy --role-name ecsTaskExecutionRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
```

## Usage

### 1. Analyze a Docker Image

- Upload a `.tar` file OR
- Enter a Docker Hub image name (e.g., `python:3.9`)

### 2. View Results

- Security vulnerabilities (from Trivy)
- Layer breakdown
- Optimization recommendations

### 3. Push to ECR

Click **"Push Original to ECR"** or **"Push Optimized to ECR"**:
- Select repository name
- Choose image tag
- Pick AWS region

### 4. Deploy to ECS

Click **"Deploy to ECS"**:
- Select ECS cluster
- Choose deployment type (Standalone Task or Service)
- Configure CPU/Memory
- Deploy!

## Project Structure

```
├── app/
│   ├── api/
│   │   ├── analyze/          # Image analysis endpoint
│   │   ├── ecr/
│   │   │   ├── auth/         # ECR authentication
│   │   │   ├── push/         # Push images to ECR
│   │   │   └── list/         # List ECR repositories
│   │   └── ecs/
│   │       ├── deploy/       # Deploy to ECS
│   │       └── status/       # Get deployment status
│   └── page.tsx              # Main UI
├── components/
│   ├── ecr-push-dialog.tsx   # ECR push UI
│   ├── ecs-deploy-dialog.tsx # ECS deploy UI
│   └── analysis-results.tsx  # Results display
├── lib/
│   ├── ecr-client.ts         # ECR operations
│   ├── ecs-deployer.ts       # ECS deployment
│   ├── docker-analyzer.ts    # Image analysis
│   ├── docker-image-optimizer.ts  # Optimization
│   └── trivy-scanner.ts      # Security scanning
```

## API Endpoints

### ECR Endpoints

- `GET /api/ecr/auth` - Get ECR credentials
- `POST /api/ecr/push` - Push image to ECR
- `GET /api/ecr/list` - List repositories/images

### ECS Endpoints

- `POST /api/ecs/deploy` - Deploy to ECS
- `GET /api/ecs/status` - Get deployment status

### Analysis Endpoints

- `POST /api/analyze` - Analyze Docker image
- `POST /api/download-image` - Download optimized image

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_REGION` | AWS region for ECR/ECS | `us-east-1` |
| `AWS_ACCESS_KEY_ID` | AWS access key | Required |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key | Required |
| `RUNTIME_OPTIMIZER_ENABLED` | Enable runtime optimization | `true` |

## Security Best Practices

1. **Never commit `.env.local`** - It contains sensitive credentials
2. **Use IAM roles** in production instead of access keys
3. **Enable ECR image scanning** (automatic with this tool)
4. **Review Trivy results** before deploying
5. **Use VPC endpoints** for ECR/ECS in production

## Troubleshooting

### Docker Not Found

```
Error: Docker is not installed or not running
```

**Solution**: Start Docker Desktop

### AWS Credentials Error

```
Error: The security token included in the request is invalid
```

**Solution**: Configure AWS CLI:

```bash
aws configure
```

### Trivy Mock Data Warning

```
Warning: Using mock vulnerability data
```

**Solution**: Install Trivy:

```bash
# Windows
winget install Aquasecurity.Trivy

# Mac
brew install trivy

# Linux
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy
```

## Cost Estimation

### ECR Storage
- $0.10 per GB/month
- Example: 500MB image = ~$0.05/month

### ECS Fargate
- vCPU: $0.04048/hour
- Memory: $0.004445/GB/hour
- Example: 0.25 vCPU + 0.5GB = ~$0.012/hour = $8.64/month (24/7)

## Contributing

PRs welcome! Please test with both local and AWS deployments.

## License

MIT
