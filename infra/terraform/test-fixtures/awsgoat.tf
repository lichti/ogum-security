# ── AWSGoat (vendored, ../awsgoat/) — end-to-end vulnerable-app validation ───
# Complements the synthetic misconfigurations above with real, exploitable
# applications. Off by default; see ../awsgoat/README.md for what each module
# deploys and why it must run in a dedicated, disposable sandbox account.
#
# Each module builds its own self-contained VPC and has no `suffix` variable
# (upstream ships fixed resource names) — running the same module twice in one
# account will collide. module-1 and module-2 can run together safely; the one
# name they originally shared (a state-files S3 bucket) was disambiguated
# during vendoring, see ../awsgoat/module-*/main.tf.

module "awsgoat_module1" {
  count  = var.create_awsgoat_module1 ? 1 : 0
  source = "../awsgoat/module-1"
}

module "awsgoat_module2" {
  count  = var.create_awsgoat_module2 ? 1 : 0
  source = "../awsgoat/module-2"
}
