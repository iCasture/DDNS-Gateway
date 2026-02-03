from __future__ import annotations  # noqa: INP001, D100

import sys
from pathlib import Path

from ddns_gateway import __version__

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"

# Ensure the project package is importable when using a src layout.
sys.path.insert(0, str(SRC_DIR))

project = "ddns_gateway"
author = "iCasture"
version = __version__
release = __version__

# -- General configuration ---------------------------------------------------

extensions = [
    # Required for numpydoc to process docstrings via autodoc events.
    "sphinx.ext.autodoc",
    # Generate summary tables (used by autoapi's show-module-summary).
    "sphinx.ext.autosummary",
    # Support for NumPy-style docstrings with validation.
    "numpydoc",
    # Automatically generate API reference pages from source code.
    "autoapi.extension",
    # Add "View Source" links to documentation.
    "sphinx.ext.viewcode",
    # Stable cross-document section references.
    "sphinx.ext.autosectionlabel",
    # Cross-project references (e.g., Python stdlib, Pydantic).
    "sphinx.ext.intersphinx",
    # Enable Markdown sources alongside reStructuredText.
    "myst_parser",
]

# Patterns to exclude from documentation build.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- autodoc configuration ---------------------------------------------------

# Display type hints in parameter descriptions for better readability.
autodoc_typehints = "description"

# -- autosummary configuration -----------------------------------------------

# Automatically generate stub files for autosummary directives.
autosummary_generate = True

# -- numpydoc configuration --------------------------------------------------

# Disable automatic class member inclusion (autoapi handles this).
numpydoc_show_class_members = False

# Enable docstring validation during build.
# "all" enables all checks; additional codes listed here are EXCLUDED.
# Excluded: ES01 (extended summary required), SA01 (See Also required),
#           EX01 (Examples required).
numpydoc_validation_checks = {"all", "ES01", "SA01", "EX01"}

# Exclude special methods and private members from validation.
numpydoc_validation_exclude = {
    r"^(?!ddns_gateway\.)",  # Exclude all packages except ddns_gateway.
    r"\.__(init|repr|str|eq|hash|len|iter|call)__$",
    r"\._",  # Private methods/attributes
}

# -- autoapi configuration ---------------------------------------------------

autoapi_type = "python"
autoapi_dirs = [str(SRC_DIR / "ddns_gateway")]
autoapi_keep_files = True  # Keep generated rst files for debugging.
autoapi_add_toctree_entry = True

# Include both class docstring and __init__ docstring.
autoapi_python_class_content = "both"

# Enable implicit namespace package support (PEP 420).
# Only needed when packages lack __init__.py files.
# This project uses traditional packages with __init__.py, so this is disabled.
# autoapi_python_use_implicit_namespaces = True

autoapi_options = [
    "members",
    "undoc-members",
    "show-inheritance",
    "show-module-summary",
    "imported-members",
]

# Custom templates directory for overriding default autoapi templates.
autoapi_template_dir = "_templates/autoapi"

# -- autosectionlabel configuration ------------------------------------------

# Prefix labels with document paths to avoid conflicts.
autosectionlabel_prefix_document = True

# -- intersphinx configuration -----------------------------------------------

# Only include projects with available objects.inv files.
# Note: FastAPI, Starlette, httpx use MkDocs and lack Sphinx inventories.
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "pydantic": ("https://docs.pydantic.dev/latest", None),
}

# -- source configuration ----------------------------------------------------

source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}

# -- HTML output configuration -----------------------------------------------

# html_theme = "sphinx_rtd_theme"
html_theme = "sphinx_book_theme"
# html_theme = "piccolo_theme"
# html_theme = "shibuya"
# html_theme = "furo"

html_static_path = ["_static"]

# -- HTML output configuration -----------------------------------------------

html_title = f"DDNS Gateway {version}"  # Set the HTML page title
