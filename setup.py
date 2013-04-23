from setuptools import setup

setup(
    name = 'pygments-IDA',
    version = '0.1',
    py_modules = ['pygments_IDA'],

    install_requires = ['pygments'],

    entry_points = {
        'pygments.lexers': 'IDAlexer = pygments_IDA:IDALexer',
    },

    author = 'Samuel (w4kfu) Chevet',
    author_email = 'samuel@lse.epita.fr',
    description = 'Pygments lexer for IDA pro disassembly',
    license = 'BSD',
    keywords = 'pygments IDA',
    url = 'http://127.0.0.1'
)
