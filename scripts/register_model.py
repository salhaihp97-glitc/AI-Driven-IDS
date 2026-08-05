"""
Model Registration and Activation CLI Utility Script.

Provides a unified command-line orchestration script to provision, index, and hot-swap 
machine learning inference assets within the system architecture without requiring an active 
Streamlit frontend lifecycle connection.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Final

# Resolve systemic workspace boundary paths dynamically prior to loading local submodules
WORKSPACE_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from core.entities.model_record import ModelRecord
from database.bootstrap import run as bootstrap_database
from services.container import Container, get_container


def main() -> None:
    """
    Parses CLI orchestration flags and executes the machine learning model registration routine.
    """
    parser = argparse.ArgumentParser(
        description="Register a newly trained machine learning asset directly into the AI-IDS operational registry."
    )
    parser.add_argument("--name", required=True, help="Distinct human-readable name tag for the model record identification.")
    parser.add_argument("--path", required=True, help="Absolute or relative file locator path referencing the binary model asset.")
    parser.add_argument("--type", default="unknown", help="Algorithmic classification metadata category descriptor (e.g. random_forest).")
    parser.add_argument("--version", default="1.0", help="Semantic layout version string for tracking iteration lineage.")
    parser.add_argument("--activate", action="store_true", help="Immediately shift the newly provisioned asset status to online.")
    parser.add_argument(
        "--exclusive", action="store_true",
        help="When combined with '--activate', ensures all other registered models are atomically scaled offline.",
    )
    
    args: Final[argparse.Namespace] = parser.parse_args()

    # Bootstrap the physical relational database schema configurations if uninitialized
    bootstrap_database()
    container: Final[Container] = get_container()

    # Assert uniqueness bounds across model entry targets prior to allocating database space
    existing: Final[ModelRecord | None] = container.model_repository.get_by_name(args.name)
    if existing is not None:
        sys.exit(
            f"Registration Blocked: A machine learning model named '{args.name}' already occupies "
            f"registry index (id={existing.id}). Use a separate --name argument or modify the existing index."
        )

    # Invoke the boundary service to parse structural layout attributes and register the model footprint
    record: Final[ModelRecord] = container.model_service.register_model(
        name=args.name, 
        file_path=args.path, 
        model_type=args.type, 
        version=args.version
    )
    print(f"Successfully indexed asset '{record.name}' [ID={record.id}] tracking {record.features_count} feature elements.")

    # Manage atomic operational runtime state activation sequences
    if args.activate:
        container.model_service.activate(record.id, exclusive=args.exclusive)
        status_message = f"Asset state [ID={record.id}] shifted to HOT operational inference mode"
        if args.exclusive:
            status_message += " (Exclusive state enforced: alternative models scaled offline)."
        print(status_message)

    print("\nOrchestration successfully processed. Access runtime dashboards to verify deployment topologies.")


if __name__ == "__main__":
    main()