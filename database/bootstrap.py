"""
Database Bootstrapping Module.

Handles single-execution system provisioning cycles upon application startup. Ensures relational 
schema state compliance idempotently and enforces initial access policy records (e.g., seeding the 
foundational administrative account) only if the persistence layer lacks existing identity profiles.
"""

from __future__ import annotations

import time
from typing import Final, Optional

from config.constants import DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USERNAME, UserRole
from core.entities.user import User
from database import schema
from database.connection import DatabaseConnection, get_db_connection
from infrastructure.logging.logger_factory import get_logger
from infrastructure.security.password_hasher import BcryptPasswordHasher
from repositories.user_repository import UserRepository

# Initialize Provisioning Subsystem Logger
logger = get_logger("database.bootstrap")


def run(db: Optional[DatabaseConnection] = None) -> None:
    """
    Executes structural schema setup validations and initial identity policy configurations.
    
    Args:
        db: Optional existing DatabaseConnection resource node. If unassigned, resolves
            a fresh connection mapping from the centralized resource pool.
    """
    logger.info("Initiating system persistence bootstrapping cycle...")
    start_time: Final[float] = time.perf_counter()
    
    connection: Final[DatabaseConnection] = db or get_db_connection()

    # Step 1: Guarantee structural database object maps exist
    schema.initialize(connection)
    logger.info("Database relational DDL layout verified and active (idempotent setup).")

    # Step 2: Validate global access policy state registries
    user_repo = UserRepository(connection)
    
    if user_repo.count() == 0:
        logger.info("Persistence layer contains zero registered user records. Initializing fallback identity seeding...")
        
        hasher = BcryptPasswordHasher()
        admin_identity = User(
            username=DEFAULT_ADMIN_USERNAME,
            password_hash=hasher.hash(DEFAULT_ADMIN_PASSWORD),
            role=UserRole.ADMIN,
        )
        
        user_repo.add(admin_identity)
        logger.warning(
            "Security Provisioning Warning: Default administrative credentials seeded (username='%s'). "
            "An immediate credentials modification password reset must occur upon initial platform access.",
            DEFAULT_ADMIN_USERNAME
        )
    else:
        logger.info("Identity persistence context already contains records. Bypassing administrative user seeding.")

    elapsed_time: Final[float] = time.perf_counter() - start_time
    logger.info("Database bootstrapping sequence completed successfully in %.3f seconds.", elapsed_time)