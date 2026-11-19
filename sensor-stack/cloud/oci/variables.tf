variable "region" {
  type        = string
  default     = "ap-singapore-1"
  description = "OCI region of the separate honeypot sensor (not existing VPN/Voice)."
}
variable "compartment_ocid" {
  type        = string
  default     = ""
  description = "Dedicated, isolated compartment OCID — no production account access."
}
variable "availability_domain" {
  type        = string
  default     = ""
  description = "Specific availability domain where Always Free capacity is verified."
}
variable "arm64_image_ocid" {
  type        = string
  default     = ""
  description = "Verified region-local Ubuntu ARM64 image OCID; never guess an ID."
}
variable "operator_ssh_public_key" {
  type        = string
  default     = ""
  description = "Public key only, never a private key."
  sensitive   = false
}
variable "admin_ssh_cidr" {
  type        = string
  default     = ""
  description = "Empty blocks port 22; when nonempty require an operator-owned /32 or /128."
  validation {
    condition = var.admin_ssh_cidr == "" || can(regex("^[0-9]{1,3}(\\.[0-9]{1,3}){3}/32$", var.admin_ssh_cidr))
    error_message = "Only one explicit IPv4 /32 is allowed for SSH administration."
  }
}
variable "launch_approved" {
  type        = bool
  default     = false
  description = "Must stay false until separate compartment, free quota, firewall, and user authorization are verified."
}
variable "public_decoys_approved" {
  type        = bool
  default     = false
  description = "Must stay false until signed listener, no-egress test and live evidence gates pass."
}
