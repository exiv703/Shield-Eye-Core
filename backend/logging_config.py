import logging
import sys
from pathlib import Path
from typing import Optional

def setup_logging(level=logging.INFO, log_file=None, log_format=None, include_timestamp=True):
    # setup default log format
    if log_format is None:
        if include_timestamp:
            log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        else:
            log_format = "[%(levelname)s] %(name)s: %(message)s"
    
    date_format = "%Y-%m-%d %H:%M:%S"
    
    handlers = []
    
    # console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_formatter = logging.Formatter(log_format, datefmt=date_format)
    console_handler.setFormatter(console_formatter)
    handlers.append(console_handler)
    
    # file handler if specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        file_handler.setLevel(level)
        file_formatter = logging.Formatter(log_format, datefmt=date_format)
        file_handler.setFormatter(file_formatter)
        handlers.append(file_handler)
    
    logging.basicConfig(
        level=level,
        format=log_format,
        datefmt=date_format,
        handlers=handlers,
        force=True
    )
    
    # quiet down noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("nmap").setLevel(logging.WARNING)

def get_logger(name):
    return logging.getLogger(name)

def set_log_level(level):
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    for handler in root_logger.handlers:
        handler.setLevel(level)

def add_file_handler(log_file, level=logging.INFO):
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    file_handler.setLevel(level)
    
    root_logger = logging.getLogger()
    if root_logger.handlers:
        formatter = root_logger.handlers[0].formatter
        file_handler.setFormatter(formatter)
    
    root_logger.addHandler(file_handler)

def enable_debug_logging(log_file=None):
    setup_logging(level=logging.DEBUG, log_file=log_file)

def enable_verbose_logging(log_file=None):
    setup_logging(level=logging.INFO, log_file=log_file)

def enable_quiet_logging():
    setup_logging(level=logging.WARNING)
