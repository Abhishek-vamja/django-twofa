from setuptools import setup, find_packages

setup(
    name="django-twofa",
    version="0.1.1",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "django>=3.2",
    ],
    description="A reusable Django app for Two-Factor Authentication.",
    author="Abhishek Vamja",
    author_email="abhishekvamja2518@gmail.com",
    url="https://github.com/Abhishek-vamja/django-twofa",
    classifiers=[
        "Framework :: Django",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
)
