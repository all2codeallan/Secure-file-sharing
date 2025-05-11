# Project Structure

```
.
├── .env
├── app.py
├── DH.py
├── DH.pyc
├── init_db.py
├── package-lock.json
├── package.json
├── requirements.txt
├── config/
│   ├── __init__.py
│   ├── db_config.py
│   └── settings.py
├── docs/
│   ├── DECRYPTION.md
│   ├── ENCRYPTION.md
│   ├── INFO.md
│   ├── project_structure.md
│   └── README_MODULARIZATION.md
├── media/
│   ├── images/
│   │   └── logo.jpg
│   ├── public-keys/
│   │   ├── admin1-1admin-PublicKey.pem
│   │   ├── admin1-ADMIN1admin-PublicKey.pem
│   │   ├── admin2-2admin-PublicKey.pem
│   │   ├── admin3-3admin-PublicKey.pem
│   │   ├── admin6-6admin-PublicKey.pem
│   │   ├── user1-1user-PublicKey.pem
│   │   └── user1-USER1user-PublicKey.pem
│   └── text-files/
├── models/
│   ├── __init__.py
│   ├── file_model.py
│   ├── session_model.py
│   ├── threshold_model.py
│   └── user_model.py
├── routes/
│   ├── __init__.py
│   ├── auth_routes.py
│   ├── dashboard_routes.py
│   ├── file_routes.py
│   └── threshold_routes.py
├── services/
│   ├── __init__.py
│   ├── auth_service.py
│   ├── file_service.py
│   ├── threshold_service.py
│   └── user_service.py
├── templates/
│   ├── base.html
│   ├── confirm-download.html
│   ├── download.html
│   ├── file-list.html
│   ├── index.html
│   ├── intro.html
│   ├── key-display.html
│   ├── login.html
│   ├── post-upload.html
│   ├── public-key-list.html
│   ├── register.html
│   ├── restore_success.html
│   ├── threshold-decrypt-confirm.html
│   ├── threshold-decrypt.html
│   ├── threshold-files-uploaded.html
│   ├── threshold-files.html
│   ├── threshold-upload.html
│   └── upload.html
└── utils/
    ├── __init__.py
    ├── auth_utils.py
    ├── crypto_utils.py
    ├── db_utils.py
    ├── dh_utils.py
    └── shamir_utils.py
