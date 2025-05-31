from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    name="agentid",
    version="0.1.0",
    packages=["agentid"],
    rust_extensions=[RustExtension("agentid.agentid", binding=Binding.PyO3)],
    setup_requires=["setuptools-rust>=0.12.0"],
    install_requires=[],
    zip_safe=False,
) 