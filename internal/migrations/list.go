package migrations

import (
	"github.com/invenlore/core/pkg/migrator"
)

func List() []migrator.Migration {
	return []migrator.Migration{
		Migration_20260114_UsersCollection_1,
		Migration_20260114_UsersUniqueEmailIndex_1,
		Migration_20260124_AuthKeysCollection_1,
		Migration_20260124_AuthKeysIndexes_1,
		Migration_20260124_RefreshSessionsCollection_1,
		Migration_20260124_RefreshSessionsIndexes_1,
		Migration_20260124_UsersAuthFields_1,
		Migration_20260125_AuthKeysRotatedAtIndex_1,
		Migration_20260204_RolesCollection_1,
		Migration_20260204_RolesIndexes_1,
		Migration_20260204_UserRolesCollection_1,
		Migration_20260204_UserRolesIndexes_1,
		Migration_20260204_RolesSeed_1,
	}
}
