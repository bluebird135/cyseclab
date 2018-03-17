# Cyseclab
## Description
This project is a website that checks a given URL's SSL certificate for vulnerabilities to certain attacks by executing and examining the information from a SSL/TLS handshake or probing the server with specifically designed payloads. It was created for the Cybersecurity lab on the TU Darmstadt in WS1017/18 and is written in Python.

## Requirements
The project requires the following:\
**Python** >3.0.0\
**pip** for python3\
**Django** >2.0.0\
**virtualenv** (optional)

## Introductory reading
If you are new to Django, the following articles may prove helpful in understanding the Django project structure:

[How To Install Django and Set Up a Development Environment on Ubuntu 16.04](https://www.digitalocean.com/community/tutorials/how-to-install-django-and-set-up-a-development-environment-on-ubuntu-16-04)\
[A Complete Beginner's Guide to Django](https://simpleisbetterthancomplex.com/series/beginners-guide/1.11/)\
[Using Git with Django](https://jeffknupp.com/blog/2012/02/07/using-git-with-django/)


## Setup
### Setting up virtualenv
#### Set up virtual environment in the _cyseclab_ folder
```
cd cyseclab
virtualenv -p python3 venv
```

#### Activate the virtual environment
```
source venv/bin/activate
```

#### Install requirements in the virtual environment
```
pip install -Ur requirements.txt
```

### Starting Django
Django can be started with the following commands. If you use virtualenv, be sure that the virtual environment is active.
```
cd cyseclab
python manage.py runserver
```

## Attacks
These are the attacks that are checked against:
* ROBOT
* Heartbleed
* BEAST
* CRIME
* POODLE
* DROWN
* Detecting deprecated or weak ciphers

For a more detailed description, see [Attacks](https://github.com/bluebird135/cyseclab/wiki/Attacks)

