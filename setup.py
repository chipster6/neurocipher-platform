"""Setup script for AuditHound"""
from setuptools import setup, find_packages

setup(
    name="audithound",
    version="0.1.0",
    description="A powerful audit and compliance tracking tool",
    packages=find_packages(),
    install_requires=[
        "flask>=2.0.0",
        "sqlalchemy>=1.4.0",
        "click>=8.0.0",
        "python-dotenv>=0.19.0",
    ],
    entry_points={
        'console_scripts': [
            'audithound=src.cli:cli',
        ],
    },
    python_requires=">=3.7",
)