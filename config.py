from json import load
import os
from dotenv import load_dotenv

load_dotenv()


# configuration for database and session management key
SQLALCHEMY_DATABASE_URI =  os.getenv('SQLALCHEMY_DATABASE_URI')                          
SECRET_KEY = os.getenv('SECRET_KEY')


# configuration for mail support
USER_ENABLE_EMAIL = False
MAIL_SERVER = os.getenv('MAIL_SERVER')
MAIL_PORT = os.getenv('MAIL_PORT')
MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')




# configuration for file uploads

UPLOAD_EXTENSIONS = os.getenv('UPLOAD_EXTENSION')
UPLOAD_PATH = os.getenv('UPLOAD_PATH')
