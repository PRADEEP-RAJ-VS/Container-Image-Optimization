# AWS ECS Network Setup Script
# This script creates necessary VPC resources for ECS deployment

Write-Host "Setting up AWS networking for ECS deployment..." -ForegroundColor Cyan
Write-Host ""

$REGION = "us-east-1"

# Check AWS CLI configuration
Write-Host "Checking AWS CLI configuration..." -ForegroundColor Yellow
$identity = aws sts get-caller-identity --output json | ConvertFrom-Json
Write-Host "Connected to AWS Account: $($identity.Account)" -ForegroundColor Green
Write-Host ""

# Get default VPC
Write-Host "Getting default VPC..." -ForegroundColor Yellow
$vpcId = aws ec2 describe-vpcs --region $REGION --filters "Name=isDefault,Values=true" --query "Vpcs[0].VpcId" --output text

if ($vpcId -eq "None" -or [string]::IsNullOrEmpty($vpcId)) {
    Write-Host "Creating default VPC..." -ForegroundColor Yellow
    aws ec2 create-default-vpc --region $REGION
    $vpcId = aws ec2 describe-vpcs --region $REGION --filters "Name=isDefault,Values=true" --query "Vpcs[0].VpcId" --output text
}

Write-Host "VPC ID: $vpcId" -ForegroundColor Green
Write-Host ""

# Get subnets
Write-Host "Getting subnets..." -ForegroundColor Yellow
$subnets = aws ec2 describe-subnets --region $REGION --filters "Name=vpc-id,Values=$vpcId" --query "Subnets[*].SubnetId" --output text
$subnetArray = $subnets -split '\s+'
Write-Host "Found $($subnetArray.Count) subnets" -ForegroundColor Green
Write-Host ""

# Create/check security group
Write-Host "Checking security group..." -ForegroundColor Yellow
$existingSG = aws ec2 describe-security-groups --region $REGION --filters "Name=group-name,Values=docker-optimizer-ecs" "Name=vpc-id,Values=$vpcId" --query "SecurityGroups[0].GroupId" --output text 2>$null

if ($existingSG -ne "None" -and -not [string]::IsNullOrEmpty($existingSG)) {
    $securityGroupId = $existingSG
    Write-Host "Security group exists: $securityGroupId" -ForegroundColor Green
}
else {
    Write-Host "Creating security group..." -ForegroundColor Yellow
    $securityGroupId = aws ec2 create-security-group --region $REGION --group-name "docker-optimizer-ecs" --description "Security group for Docker Optimizer ECS tasks" --vpc-id $vpcId --output text
    Write-Host "Created security group: $securityGroupId" -ForegroundColor Green
    
    Write-Host "Adding ingress rules..." -ForegroundColor Yellow
    aws ec2 authorize-security-group-ingress --region $REGION --group-id $securityGroupId --protocol tcp --port 80 --cidr 0.0.0.0/0 2>$null
    aws ec2 authorize-security-group-ingress --region $REGION --group-id $securityGroupId --protocol tcp --port 443 --cidr 0.0.0.0/0 2>$null
    aws ec2 authorize-security-group-ingress --region $REGION --group-id $securityGroupId --protocol tcp --port 8080 --cidr 0.0.0.0/0 2>$null
    aws ec2 authorize-security-group-ingress --region $REGION --group-id $securityGroupId --protocol tcp --port 3000 --cidr 0.0.0.0/0 2>$null
    Write-Host "Added ingress rules" -ForegroundColor Green
}
Write-Host ""

# Create/check ECS cluster
Write-Host "Checking ECS cluster..." -ForegroundColor Yellow
$existingCluster = aws ecs describe-clusters --region $REGION --clusters "docker-optimizer-cluster" --query "clusters[0].status" --output text 2>$null

if ($existingCluster -eq "ACTIVE") {
    Write-Host "ECS cluster exists: docker-optimizer-cluster" -ForegroundColor Green
}
else {
    Write-Host "Creating ECS cluster..." -ForegroundColor Yellow
    aws ecs create-cluster --region $REGION --cluster-name "docker-optimizer-cluster" | Out-Null
    Write-Host "Created ECS cluster: docker-optimizer-cluster" -ForegroundColor Green
}
Write-Host ""

# Update .env.local
Write-Host "Updating .env.local..." -ForegroundColor Yellow
$envContent = Get-Content .env.local -Raw

if ($envContent -notmatch "ECS_SUBNET_IDS") {
    $subnetList = $subnetArray -join ","
    $networkConfig = "`n# ECS Network Configuration`nECS_SUBNET_IDS=$subnetList`nECS_SECURITY_GROUP_IDS=$securityGroupId`nECS_ASSIGN_PUBLIC_IP=true`n"
    Add-Content -Path .env.local -Value $networkConfig
    Write-Host "Updated .env.local with network configuration" -ForegroundColor Green
}
else {
    Write-Host "Network configuration already exists in .env.local" -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "AWS ECS Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuration:" -ForegroundColor White
Write-Host "  VPC: $vpcId" -ForegroundColor Gray
Write-Host "  Subnets: $($subnetArray.Count) configured" -ForegroundColor Gray
Write-Host "  Security Group: $securityGroupId" -ForegroundColor Gray
Write-Host "  ECS Cluster: docker-optimizer-cluster" -ForegroundColor Gray
Write-Host ""
Write-Host "Ready to deploy! Run: pnpm dev" -ForegroundColor Green
Write-Host ""

