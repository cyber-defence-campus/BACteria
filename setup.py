from setuptools import setup, find_packages

setup(
    name="BACteria",  
    version="0.1.0",  
    author="Visergon",
    description="A simple discovery and pentest tool for BACnet services",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/my_project", #TODO  
    packages=find_packages(),  
    install_requires=[
        "websockets",
        "aiofiles",
        "colorama"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
