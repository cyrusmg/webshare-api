from setuptools import setup, find_packages

setup(
    name='webshare',
    version='1.0',
    packages=['webshare'],
    install_requires = [
        "requests",
        "passlib",
        ]
    )
