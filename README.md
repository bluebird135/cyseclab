# Cyseclab
## Setting up Django
### Tools & Packages
python3 --version    //Python 3.6.3

pip3 --version       //pip 9.0.1

Django               //v. 2.0.3

### Setup
Basic Guide unter https://medium.com/@djstein/modern-django-part-0-introduction-and-initial-setup-657df48f08f8
Guides die die Projektsturktur und Django Komponenten erklären:
https://djangoforbeginners.com/hello-world/
https://docs.djangoproject.com/en/2.0/intro/tutorial01/

#### 1. Im "/cyseclab" Verzeichnis venv aufsetzten
```virtualenv -p python3 venv```

Per default wird das Verzeichnis von der .gitignore ignoriert also bei jedem neuem clonen einmal ausfuehren.

#### 2. Django im venv installieren
Activate the virtualenv venv
```source venv/bin/activate```

Install Django via pip installing all dependencies in requirements.txt
```pip install -Ur requirements.txt```

### Ausführen
Im "/cyseclab" Verzeichnis venv ausführen
```source venv/bin/activate```

Testserver starten (zmd. bis an Apache angebunden)
```python manage.py runserver```
