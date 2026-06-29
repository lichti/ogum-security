'use client'
import { Search } from 'lucide-react'

interface FiltersProps {
  onSearch: (search: string) => void
  onResourceType: (type: string) => void
  onRegion: (region: string) => void
}

export function Filters({ onSearch, onResourceType, onRegion }: FiltersProps) {
  return (
    <div className="flex gap-3 items-center">
      <div className="relative flex-1 max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
        <input
          type="text"
          placeholder="Search by name, ARN, or ID..."
          onChange={(e) => onSearch(e.target.value)}
          className="w-full pl-9 pr-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-orange-500"
        />
      </div>
      <select
        onChange={(e) => onResourceType(e.target.value)}
        defaultValue=""
        className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-orange-500"
      >
        <option value="">All types</option>
        <option value="ec2_instance">EC2 Instance</option>
        <option value="vpc">VPC</option>
        <option value="subnet">Subnet</option>
        <option value="security_group">Security Group</option>
        <option value="rds_instance">RDS Instance</option>
        <option value="lambda_function">Lambda Function</option>
        <option value="eks_cluster">EKS Cluster</option>
        <option value="s3_bucket">S3 Bucket</option>
        <option value="kms_key">KMS Key</option>
      </select>
      <select
        onChange={(e) => onRegion(e.target.value)}
        defaultValue=""
        className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-orange-500"
      >
        <option value="">All regions</option>
        <option value="us-east-1">us-east-1</option>
        <option value="us-west-2">us-west-2</option>
        <option value="eu-west-1">eu-west-1</option>
        <option value="sa-east-1">sa-east-1</option>
        <option value="ap-southeast-1">ap-southeast-1</option>
      </select>
    </div>
  )
}
