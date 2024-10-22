from setuptools import setup, find_packages

setup(
    name='sqlinjfindx',  
    version='1.3',  
    packages=find_packages(),  
    install_requires=[  
        'termcolor',  
    ],
    entry_points={  
        'console_scripts': [
            'sqlinjfindx=sqlinjfindx:main',  
        ],
    },
    classifiers=[  
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',  
)
