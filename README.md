Go to live! kata
==================================

Contained in this repo, there are some instructions for a new application that will go live in the next month!

You will need to:

1. Fork this repository.

2. Automate the creation of the infrastructure and the setup of the application.

   You have only these instructions:

   2.1 It works on Ubuntu Linux 14.04 x64

   2.2 It's based on the last version of WordPress (it will be more useful if we can parameterize the version)

   2.3 You can choose Apache, Nginx or whatever you want

   For any other issues or question you will have to ask to the developers. In this case please ask us without problems :)

3. Once deployed, the application should be secure, fast and stable. Assume that the machine is running on the public Internet and should be hardened and locked down.

4. Make any assumptions that you need to. This is an opportunity to showcase your skills, so if you want to, implement the deployment process with any additional features, tools or techniques you'd like to.

5. We are evaluating solutions based on the architecture and quality of the deployment. Show us just how beautiful, clean and pragmatic your code can be.

6. Once your solution is ready, please send us the link of your project.

Description
=================================
The script is written in python and works with Amazon Web Services using boto and fabric libraries.
It creates a new vpc, a new subnet and a new security group,
then launches a machine and deploy mysql, apache and configure wordpress.

Dependencies
=================================
1. Aws account configured with access key and ssh key

2. Ubuntu environment. For different os read 'Vagrant file' section
   I recommend to work in a python virtual environment.
   For Ubuntu os (tested on 14.04 and 15.04):
   * sudo apt-get install python-dev python-virtualenv virtualenvwrapper
   * mkvirtualenv aws-wordpress
   * workon aws-wordpress
   * pip install -r requirements.txt

Vagrant file
===============================
For os different from ubuntu I put a Vagrant file that deploy a machine ready for running the script.
It needs virtualbox and vagrant.
1. cd vagrant
2. vagrant up
3. After the process ends you need to load /home/vagrant/.ssh/id_rsa.pub in aws
4. vagrant ssh
The script is cloned in the home folder (/home/vagrant/go-to-live-kata)

How to
================================
In the folder 'deploy' there are two files:
* deploy_wordpress.py: main script file
* variable.py: file with variables used for deployment

1. Open variable.py file and edit the variables. 
2. Launch the script with:
```
   python deploy/deploy_wordpress.py --access-key _ACCESS_KEY_ --secret-key _SECRETKEY_ --ssh-key _KEYPAIRNAME_
```
   Note the KEY_PAIR_NAME is the name of the key and must correspond with the public key declared in KEY_FILE

3. Wait for the script finishing. At the end the ip of the wordpress instance will be print

