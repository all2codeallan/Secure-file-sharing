# Project Modularization Documentation

## Overview

This document outlines the modularization changes made to the Secure File Sharing Using Cloud application. The project has been restructured to follow a more modular architecture, separating concerns into distinct services and routes.

## Project Structure

The application now follows this structure:

```
Web_app/
├── app.py       # New modular application entry point
├── models/                 # Database models
│   ├── __init__.py
│   ├── file_model.py
│   ├── session_model.py
│   ├── threshold_model.py
│   └── user_model.py
├── services/               # Business logic services
│   ├── __init__.py
│   ├── auth_service.py
│   ├── file_service.py
│   ├── threshold_service.py
│   └── user_service.py
├── routes/                 # Route handlers
│   ├── __init__.py
│   ├── auth_routes.py
│   ├── file_routes.py
│   └── threshold_routes.py
└── utils/                  # Utility functions
    ├── __init__.py
    ├── auth_utils.py
    ├── crypto_utils.py
    ├── db_utils.py
    └── ...
```

## Modularization Changes

### Services

The business logic has been extracted from the monolithic `app.py` into separate service modules:

1. **auth_service.py**: Authentication-related functionality
2. **file_service.py**: File handling operations (upload, download, encryption)
3. **threshold_service.py**: Threshold encryption operations
4. **user_service.py**: User management operations

### Routes

The route handlers have been organized into separate blueprint modules:

1. **auth_routes.py**: Authentication routes (login, register, logout)
2. **file_routes.py**: File operation routes (upload, download, listing)
3. **threshold_routes.py**: Threshold encryption routes

### Application Entry Point

The `app_refactored.py` file serves as the new application entry point, registering all the blueprints and setting up the application configuration.

## How to Use

To use the refactored application:

1. Run `app_refactored.py` instead of the original `app.py`
2. All functionality remains the same, but the code is now more maintainable and easier to extend

## Benefits of Modularization

1. **Separation of Concerns**: Each module has a specific responsibility
2. **Improved Maintainability**: Easier to understand and modify specific parts of the application
3. **Better Testability**: Services can be tested independently
4. **Scalability**: New features can be added with minimal changes to existing code
5. **Code Reusability**: Services can be reused across different parts of the application

## Migration Plan

The application can be gradually migrated from the monolithic structure to the modular structure:

1. Start using `app_refactored.py` in development
2. Test thoroughly to ensure all functionality works as expected
3. Once verified, replace `app.py` with the refactored version