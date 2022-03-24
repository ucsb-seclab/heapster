
try:
    from setuptools import setup
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    from distutils.core import setup
    import os
    packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]

setup(
    name='ailment',
    version='8.20.6.1',
    python_requires='>=3.6',
    packages=packages,
    install_requires=[],
    description='The angr intermediate language.',
    url='https://github.com/angr/ailment',
)
