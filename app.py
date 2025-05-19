from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
import os
import hashlib
import random
import secrets

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
