"""
it's a file organizer script, it organizes files in a directory into subdirectories based on file types (like images, documents, videos, etc.) and optionally by date (year-month). It can also watch a directory for new files and organize them automatically as they arrive.
This is very handy, unless you like a messy desktop or downloads folder... who does.. right? (totally not me, that's why I made this..)

Aymen
"""

import os
import shutil
import time
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import argparse


# File type categories
FILE_CATEGORIES: Dict[str, List[str]] = {
    'Images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.ico'],
    'Documents': ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt', '.xls', '.xlsx', '.ppt', '.pptx'],
    'Videos': ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm'],
    'Audio': ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a', '.wma'],
    'Archives': ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'],
    'Code': ['.py', '.js', '.java', '.cpp', '.c', '.h', '.cs', '.php', '.rb', '.go', '.rs'],
    'Data': ['.csv', '.json', '.xml', '.yaml', '.yml', '.sql', '.db', '.sqlite'],
    'Executables': ['.exe', '.msi', '.dmg', '.deb', '.rpm', '.appimage']
}


def setup_logging(log_file: Optional[str] = None) -> None:
    """Configure logging for the application."""
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    
    if log_file:
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    else:
        logging.basicConfig(level=logging.INFO, format=log_format)


def get_file_category(file_extension: str) -> str:
    """
    Determine the category of a file based on its extension.
    
    Args:
        file_extension: File extension (e.g., '.jpg')
    
    Returns:
        Category name or 'Others' if no match found
    """
    file_extension = file_extension.lower()
    
    for category, extensions in FILE_CATEGORIES.items():
        if file_extension in extensions:
            return category
    
    return 'Others'


def organize_file(file_path: Path, base_dir: Path, organize_by_date: bool = False) -> None:
    """
    Move a file to its appropriate category folder.
    
    Args:
        file_path: Path to the file to organize
        base_dir: Base directory for organization
        organize_by_date: If True, create date-based subdirectories
    """
    if not file_path.exists() or file_path.is_dir():
        return
    
    # Skip hidden files and system files
    if file_path.name.startswith('.'):
        return
    
    try:
        # Determine category
        file_extension = file_path.suffix
        category = get_file_category(file_extension)
        
        # Create category directory
        if organize_by_date:
            # Get file modification date
            mod_time = datetime.fromtimestamp(file_path.stat().st_mtime)
            date_folder = mod_time.strftime('%Y-%m')
            target_dir = base_dir / category / date_folder
        else:
            target_dir = base_dir / category
        
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # Handle duplicate filenames
        target_path = target_dir / file_path.name
        counter = 1
        base_name = file_path.stem
        
        while target_path.exists():
            new_name = f"{base_name}_{counter}{file_extension}"
            target_path = target_dir / new_name
            counter += 1
        
        # Move the file
        shutil.move(str(file_path), str(target_path))
        logging.info(f"Moved: {file_path.name} -> {target_path.relative_to(base_dir)}")
    
    except Exception as e:
        logging.error(f"Error organizing {file_path.name}: {e}")


def organize_directory(directory: Path, organize_by_date: bool = False) -> None:
    """
    Organize all files in a directory once.
    
    Args:
        directory: Directory to organize
        organize_by_date: Whether to organize by date subdirectories
    """
    logging.info(f"Starting organization of {directory}")
    
    files = [f for f in directory.iterdir() if f.is_file()]
    
    for file_path in files:
        organize_file(file_path, directory, organize_by_date)
    
    logging.info(f"Organization complete. Processed {len(files)} files.")


class FileOrganizerHandler(FileSystemEventHandler):
    """Watch directory for new files and organize them automatically."""
    
    def __init__(self, base_dir: Path, organize_by_date: bool = False):
        self.base_dir = base_dir
        self.organize_by_date = organize_by_date
    
    def on_created(self, event):
        """Handle file creation events."""
        if not event.is_directory:
            file_path = Path(event.src_path)
            # Wait a moment to ensure file is fully written
            time.sleep(1)
            organize_file(file_path, self.base_dir, self.organize_by_date)


def watch_directory(directory: Path, organize_by_date: bool = False) -> None:
    """
    Continuously watch a directory and organize new files.
    
    Args:
        directory: Directory to watch
        organize_by_date: Whether to organize by date subdirectories
    """
    logging.info(f"Starting directory watcher for {directory}")
    logging.info("Press Ctrl+C to stop...")
    
    event_handler = FileOrganizerHandler(directory, organize_by_date)
    observer = Observer()
    observer.schedule(event_handler, str(directory), recursive=False)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logging.info("Stopping directory watcher...")
    
    observer.join()


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Organize files in a directory by type and optionally by date'
    )
    parser.add_argument(
        'directory',
        type=str,
        help='Directory to organize'
    )
    parser.add_argument(
        '--watch',
        action='store_true',
        help='Continuously watch directory for new files'
    )
    parser.add_argument(
        '--by-date',
        action='store_true',
        help='Organize files into date-based subdirectories (YYYY-MM)'
    )
    parser.add_argument(
        '--log-file',
        type=str,
        help='Path to log file (optional)'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_file)
    
    # Validate directory
    directory = Path(args.directory).resolve()
    if not directory.exists():
        logging.error(f"Directory does not exist: {directory}")
        return
    
    if not directory.is_dir():
        logging.error(f"Path is not a directory: {directory}")
        return
    
    # Organize or watch
    if args.watch:
        watch_directory(directory, args.by_date)
    else:
        organize_directory(directory, args.by_date)


if __name__ == '__main__':
    main()