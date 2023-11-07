output "neuwerk_bastion_ip" {
  value = module.neuwerk.bastion_ip
}

output "apps_bastion_ip" {
  value = module.apps.bastion_ip
}

output "apps_testbox_ip" {
  value = module.apps.test_box_ip
}

output "neuwerk_testbox_ip" {
  value = module.neuwerk.testbox_ip_internal
}
