# Apache Brooklyn ansible external inventory script

Ansible dynamic inventory for apache brooklyn

Generates inventory that Ansible can understand by making API requests to Apache Brooklyn.

The default configuration file is named 'brooklyn.ini' and is located alongside this script. You can
choose any other file by setting the BROOKLYN_INI_PATH environment variable.

If param 'application_id' is left blank in 'brooklyn.ini', the inventory includes all the instances
in application where the requesting user belongs. Otherwise, only instances from the given project
are included, provided the requesting user belongs to it.

The following variables are established for every host. They can be retrieved from the hostvars
dictionary.
 - app_name: str
 - app_description: str
 - app_status: str
 - app_tags: list(str)
 - app_internal_ips: list(str)
 - app_external_ips: list(str)
 - app_created_at
 - app_updated_at
 - ansible_ssh_host

Instances are grouped by the following categories:
 - tag:
   A group is created for each tag. E.g. groups 'tag_foo' and 'tag_bar' are created if there exist
   instances with tags 'foo' and/or 'bar'.
 - application:
   A group is created for each application. E.g. group 'application_test' is created if an
   applicationproject named 'test' exist.
 - status:
   A group is created for each instance state. E.g. groups 'status_RUNNING' and 'status_PENDING'
   are created if there are instances in running and pending state.

Examples:
  Execute uname on all instances in application 'test'
  $ ansible -i brooklyn.py application_test -m shell -a "/bin/uname -a"

  Install nginx on all debian web servers tagged with 'www'
  $ ansible -i brooklyn.py tag_www -m apt -a "name=nginx state=present"

  Run site.yml playbook on web servers
  $ ansible-playbook -i brooklyn.py site.yml -l tag_www

  $ export ANSIBLE_HOST_KEY_CHECKING=False
  $ dos2unix brooklyn.py
  $ ansible -i brooklyn.py all -m apt -a "name=nginx state=present" --become --become-user=root
 
Support:
  This script is tested on Python 2.7 and 3.5. It may work on other versions though.
