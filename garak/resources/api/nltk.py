"""Loader for nltk to enable common configuration in garak"""

import nltk as _nltk
import sys
from logging import getLogger
from pathlib import Path

from garak import _config


logger = getLogger(__name__)


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


_nltk_data_path = _config.transient.cache_dir / "data" / "nltk_data"
_nltk.data.path.append(str(_nltk_data_path))
_download_path = _nltk_data()


# override the default download path
def download(
    info_or_id=None,
    download_dir=_download_path,
    quiet=True,
    force=False,
    prefix="[nltk_data] ",
    halt_on_error=True,
    raise_on_error=False,
    print_error_to=sys.stderr,
):
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


data = _nltk.data
word_tokenize = _nltk.word_tokenize
pos_tag = _nltk.pos_tag
