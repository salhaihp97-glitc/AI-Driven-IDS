"""
Authentication and Identity Management Service Module.

Serves as the exclusive application gateway coordinating identity verification workflows. 
Encapsulates operations regarding security token verification, state mutation assertions, 
and user property validations, separating data access layouts completely from presentation interfaces.
"""

from __future__ import annotations

from typing import Final

from config.constants import LogLevel, LogSource
from core.entities.log_entry import LogEntry
from core.entities.user import User
from core.exceptions import AuthenticationError, ValidationError
from core.interfaces.security import IPasswordHasher
from infrastructure.logging.logger_factory import get_logger
from repositories.log_repository import LogRepository
from repositories.user_repository import UserRepository
from utils.time_utils import utc_now_sql
from utils.validators import validate_password_strength, validate_username

logger = get_logger("services.auth_service")


class AuthService:
    """
    Core application component managing access controls, security verification, and credential lifecycle mutations.
    """

    def __init__(
        self,
        user_repository: UserRepository,
        password_hasher: IPasswordHasher,
        log_repository: LogRepository | None = None,
    ) -> None:
        """
        Initializes the identity authentication manager with essential cryptographic and persistence adapters.
        """
        self._users: Final[UserRepository] = user_repository
        self._hasher: Final[IPasswordHasher] = password_hasher
        self._logs: Final[LogRepository | None] = log_repository

    def _log(self, level: LogLevel, message: str) -> None:
        """
        Appends an execution event tracing history state directly into the system audit repository.
        """
        if self._logs is not None:
            self._logs.add(LogEntry(source=LogSource.USER, level=level, message=message))

    def login(self, username: str, password: str) -> User:
        """
        Authenticates a system identity profile using credential validation sets.

        Args:
            username: Plain text credentials identifying a specific account locator string.
            password: The plain text verification password to authenticate.

        Returns:
            The authenticated domain User instance containing validated profile attributes.

        Raises:
            AuthenticationError: On blank input arrays, missing accounts, or incorrect matches.
        """
        sanitized_username: Final[str] = (username or "").strip()
        if not sanitized_username or not password:
            raise AuthenticationError("Access Restriction: Username and password credentials cannot be null values.")

        user: Final[User | None] = self._users.get_by_username(sanitized_username)
        if user is None or not user.is_active:
            logger.warning("Security Exception: Denied login attempt targeting inactive or missing identity profile '%s'", sanitized_username)
            self._log(LogLevel.WARNING, f"Denied login attempt targeting inactive or missing identity profile '{sanitized_username}'.")
            raise AuthenticationError("Authentication Failure: Invalid username configuration or secret password key match.")

        if not self._hasher.verify(password, user.password_hash):
            logger.warning("Security Exception: Denied login attempt (cryptographic verification mismatch) for profile '%s'", sanitized_username)
            self._log(LogLevel.WARNING, f"Denied login attempt (cryptographic verification mismatch) for profile '{sanitized_username}'.")
            raise AuthenticationError("Authentication Failure: Invalid username configuration or secret password key match.")

        # Update metadata state properties tracking historical login timestamps
        user.last_login_at = utc_now_sql()
        self._users.update(user)
        
        logger.info("Security Context: Profile identity '%s' successfully established an active session context.", sanitized_username)
        self._log(LogLevel.INFO, f"Profile identity '{sanitized_username}' successfully established an active session context.")
        return user

    def change_password(self, user: User, current_password: str, new_password: str) -> None:
        """
        Alters the active encryption key associated with a specific operational profile user context.

        Args:
            user: The target authenticated domain entity updating values.
            current_password: The previous secret verification key value.
            new_password: The proposed replacement secret validation string.

        Raises:
            AuthenticationError: If current password values do not verify securely.
            ValidationError: If the incoming character array does not fulfill complexity metrics.
        """
        if not self._hasher.verify(current_password, user.password_hash):
            self._log(LogLevel.WARNING, f"Security Exception: Denied password revision sequence for user '{user.username}' (invalid current verification key).")
            raise AuthenticationError("Authentication Failure: The provided current verification secret key is incorrect.")
            
        validate_password_strength(new_password)
        
        user.password_hash = self._hasher.hash(new_password)
        self._users.update(user)
        
        logger.info("Security Action: Cryptographic hash modifications committed successfully for user account '%s'.", user.username)
        self._log(LogLevel.INFO, f"Cryptographic hash modifications committed successfully for user account '{user.username}'.")

    def change_username(self, user: User, new_username: str) -> User:
        """
        Reconfigures the structural access identification handle allocated to a specific registration profile.

        Args:
            user: The target tracking domain user entity instance to modify.
            new_username: The distinct new target name mapping request string.

        Returns:
            The synchronized and persistent mutated domain user entity model object.

        Raises:
            ValidationError: If alignment filters trip, or if the resource alias collision occurs.
        """
        validated_name: Final[str] = validate_username(new_username)
        existing: Final[User | None] = self._users.get_by_username(validated_name)
        
        if existing is not None and existing.id != user.id:
            raise ValidationError(f"Identity Access Collision: The requested lookup alias identifier '{validated_name}' is already assigned.")
            
        old_username: Final[str] = user.username
        user.username = validated_name
        self._users.update(user)
        
        logger.info("Identity Action: Profile lookup index changed to '%s' [Account Index ID=%s].", validated_name, user.id)
        self._log(LogLevel.INFO, f"Identity Action: Profile lookup index changed from '{old_username}' to '{validated_name}' [Account Index ID={user.id}].")
        return user

    def get_user_by_id(self, user_id: int) -> User | None:
        """
        Resolves a single structured profile description using its primary identifier index integer.
        """
        return self._users.get_by_id(user_id)