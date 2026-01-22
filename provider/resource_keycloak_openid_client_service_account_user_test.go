package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/keycloak/terraform-provider-keycloak/keycloak"
)

func TestAccKeycloakOpenidClientServiceAccountUser_basic(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc-test")
	resourceName := "keycloak_openid_client_service_account_user.test"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckKeycloakOpenidClientServiceAccountUserAttributesCleared(resourceName),
		Steps: []resource.TestStep{
			{
				Config: testAccKeycloakOpenidClientServiceAccountUserConfig_basic(clientId),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "realm_id", testAccRealm.Realm),
					resource.TestMatchResourceAttr(resourceName, "service_account_user_id", regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$")),
					resource.TestCheckResourceAttr(resourceName, "username", "service-account-"+clientId),
					resource.TestCheckResourceAttr(resourceName, "attributes.key1", "value1"),
					resource.TestCheckResourceAttr(resourceName, "attributes.key2", "value2"),
				),
			},
		},
	})
}

func TestAccKeycloakOpenidClientServiceAccountUser_updateAttributes(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc-test")
	resourceName := "keycloak_openid_client_service_account_user.test"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckKeycloakOpenidClientServiceAccountUserAttributesCleared(resourceName),
		Steps: []resource.TestStep{
			{
				Config: testAccKeycloakOpenidClientServiceAccountUserConfig_basic(clientId),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "attributes.key1", "value1"),
					resource.TestCheckResourceAttr(resourceName, "attributes.key2", "value2"),
				),
			},
			{
				Config: testAccKeycloakOpenidClientServiceAccountUserConfig_updated(clientId),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "attributes.key1", "updated_value1"),
					resource.TestCheckResourceAttr(resourceName, "attributes.key3", "value3"),
					resource.TestCheckNoResourceAttr(resourceName, "attributes.key2"),
				),
			},
		},
	})
}

func TestAccKeycloakOpenidClientServiceAccountUser_userFields(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc-test")
	resourceName := "keycloak_openid_client_service_account_user.test"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckKeycloakOpenidClientServiceAccountUserAttributesCleared(resourceName),
		Steps: []resource.TestStep{
			{
				Config: testAccKeycloakOpenidClientServiceAccountUserConfig_userFields(clientId),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "email", "service-account@example.com"),
					resource.TestCheckResourceAttr(resourceName, "email_verified", "true"),
					resource.TestCheckResourceAttr(resourceName, "first_name", "Service"),
					resource.TestCheckResourceAttr(resourceName, "last_name", "Account"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
				),
			},
		},
	})
}

func TestAccKeycloakOpenidClientServiceAccountUser_import(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc-test")
	resourceName := "keycloak_openid_client_service_account_user.test"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckKeycloakOpenidClientServiceAccountUserAttributesCleared(resourceName),
		Steps: []resource.TestStep{
			{
				Config: testAccKeycloakOpenidClientServiceAccountUserConfig_basic(clientId),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "attributes.key1", "value1"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCheckKeycloakOpenidClientServiceAccountUserAttributesCleared(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return nil
		}

		realmId := rs.Primary.Attributes["realm_id"]
		serviceAccountUserId := rs.Primary.Attributes["service_account_user_id"]

		keycloakClient := testAccProvider.Meta().(*keycloak.KeycloakClient)

		user, err := keycloakClient.GetUser(testCtx, realmId, serviceAccountUserId)
		if err != nil {
			if keycloak.ErrorIs404(err) {
				return nil
			}
			return err
		}

		if len(user.Attributes) > 0 {
			return fmt.Errorf("service account user still has attributes: %v", user.Attributes)
		}

		return nil
	}
}

func testAccKeycloakOpenidClientServiceAccountUserConfig_basic(clientId string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client" "test" {
	name                     = "%s"
	client_id                = "%s"
	realm_id                 = data.keycloak_realm.realm.id
	access_type              = "CONFIDENTIAL"
	service_accounts_enabled = true
	client_secret            = "secret"
}

resource "keycloak_openid_client_service_account_user" "test" {
	realm_id                = data.keycloak_realm.realm.id
	service_account_user_id = keycloak_openid_client.test.service_account_user_id

	attributes = {
		"key1" = "value1"
		"key2" = "value2"
	}
}
`, testAccRealm.Realm, clientId, clientId)
}

func testAccKeycloakOpenidClientServiceAccountUserConfig_updated(clientId string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client" "test" {
	name                     = "%s"
	client_id                = "%s"
	realm_id                 = data.keycloak_realm.realm.id
	access_type              = "CONFIDENTIAL"
	service_accounts_enabled = true
	client_secret            = "secret"
}

resource "keycloak_openid_client_service_account_user" "test" {
	realm_id                = data.keycloak_realm.realm.id
	service_account_user_id = keycloak_openid_client.test.service_account_user_id

	attributes = {
		"key1" = "updated_value1"
		"key3" = "value3"
	}
}
`, testAccRealm.Realm, clientId, clientId)
}

func testAccKeycloakOpenidClientServiceAccountUserConfig_userFields(clientId string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client" "test" {
	name                     = "%s"
	client_id                = "%s"
	realm_id                 = data.keycloak_realm.realm.id
	access_type              = "CONFIDENTIAL"
	service_accounts_enabled = true
	client_secret            = "secret"
}

resource "keycloak_openid_client_service_account_user" "test" {
	realm_id                = data.keycloak_realm.realm.id
	service_account_user_id = keycloak_openid_client.test.service_account_user_id

	email          = "service-account@example.com"
	email_verified = true
	first_name     = "Service"
	last_name      = "Account"
	enabled        = true

	attributes = {
		"key1" = "value1"
	}
}
`, testAccRealm.Realm, clientId, clientId)
}
