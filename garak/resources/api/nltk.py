"""Loader for nltk to enable common configuration in garak"""

import sys
from logging import getLogger
from pathlib import Path

logger = getLogger(__name__)

# Lazy-loaded nltk module and its attributes
_nltk = None
_nltk_data_path = None
_download_path = None
_initialized = False


def _ensure_initialized():
    """Lazily initialize nltk configuration."""
    global _nltk, _nltk_data_path, _download_path, _initialized
    if _initialized:
        return
    
    import nltk as nltk_module
    from garak import _config
    
    _nltk = nltk_module
    _nltk_data_path = _config.transient.cache_dir / "data" / "nltk_data"
    _nltk.data.path.append(str(_nltk_data_path))
    _download_path = _nltk_data()
    _initialized = True


def _nltk_data():
    """Set nltk_data location, if an existing default is found utilize it, otherwise add to project's cache location."""
    from nltk.downloader import Downloader

    default_path = Path(Downloader().default_download_dir())
    if not default_path.exists():
        # if path not found then place in the user cache
        # get env var for NLTK_DATA, fallback to create in cachedir / nltk_data
        logger.debug("nltk_data location not found using project cache location")
        _nltk_data_path.mkdir(mode=0o740, parents=True, exist_ok=True)
        default_path = _nltk_data_path
    return default_path


# override the default download path
def download(
    info_or_id=None,
    download_dir=None,
    quiet=True,
    force=False,
    prefix="[nltk_data] ",
    halt_on_error=True,
    raise_on_error=False,
    print_error_to=sys.stderr,
):
    _ensure_initialized()
    if download_dir is None:
        download_dir = _download_path
    return _nltk.download(
        info_or_id,
        download_dir,
        quiet,
        force,
        prefix,
        halt_on_error,
        raise_on_error,
        print_error_to,
    )


class _LazyNltkData:
    """Lazy accessor for nltk.data."""
    
    def __getattr__(self, name):
        _ensure_initialized()
        return getattr(_nltk.data, name)
    
    def find(self, *args, **kwargs):
        _ensure_initialized()
        return _nltk.data.find(*args, **kwargs)


class _LazyNltkModule:
    """Lazy accessor for nltk module functions."""
    
    def word_tokenize(self, *args, **kwargs):
        _ensure_initialized()
        return _nltk.word_tokenize(*args, **kwargs)
    
    def pos_tag(self, *args, **kwargs):
        _ensure_initialized()
        return _nltk.pos_tag(*args, **kwargs)


data = _LazyNltkData()
_lazy_module = _LazyNltkModule()
word_tokenize = _lazy_module.word_tokenize
pos_tag = _lazy_module.pos_tag
