from setuptools import setup, find_packages

setup(
    name="bitescanner",
    version="0.1.0",
    packages=find_packages(),
    install_requires=open('requirements.txt').read().splitlines(),
    entry_points={'console_scripts': ['bitescanner=main:main']},
    include_package_data=True,
    package_data={
        'scanner': ['data/*.json', 'data/*.txt']
    }
)