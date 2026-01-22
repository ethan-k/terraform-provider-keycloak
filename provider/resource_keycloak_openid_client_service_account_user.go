package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/keycloak/terraform-provider-keycloak/keycloak"
)

func resourceKeycloakOpenidClientServiceAccountUser() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceKeycloakOpenidClientServiceAccountUserCreate,
		ReadContext:   resourceKeycloakOpenidClientServiceAccountUserRead,
		UpdateContext: resourceKeycloakOpenidClientServiceAccountUserUpdate,
		DeleteContext: resourceKeycloakOpenidClientServiceAccountUserDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceKeycloakOpenidClientServiceAccountUserImport,
		},
		Schema: map[string]*schema.Schema{
			"realm_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The realm this service account user belongs to.",
			},
			"service_account_user_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The ID of the service account user. This is typically obtained from keycloak_openid_client.service_account_user_id.",
			},
			"username": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The username of the service account user.",
			},
			"email": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The email of the service account user.",
			},
			"email_verified": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether the email address has been verified.",
			},
			"first_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The first name of the service account user.",
			},
			"last_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The last name of the service account user.",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Whether the service account user is enabled.",
			},
			"attributes": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "A map of custom attributes to add to the service account user. Use `##` to specify multiple values for a single attribute key.",
			},
		},
	}
}

func mapFromDataToServiceAccountUser(data *schema.ResourceData) *keycloak.User {
	attributes := map[string][]string{}

	if v, ok := data.GetOk("attributes"); ok {
		for key, value := range v.(map[string]interface{}) {
			attributes[key] = strings.Split(value.(string), MULTIVALUE_ATTRIBUTE_SEPARATOR)
		}
	}

	return &keycloak.User{
		Id:            data.Get("service_account_user_id").(string),
		RealmId:       data.Get("realm_id").(string),
		Email:         data.Get("email").(string),
		EmailVerified: data.Get("email_verified").(bool),
		FirstName:     data.Get("first_name").(string),
		LastName:      data.Get("last_name").(string),
		Enabled:       data.Get("enabled").(bool),
		Attributes:    attributes,
	}
}

func mapFromServiceAccountUserToData(data *schema.ResourceData, user *keycloak.User) {
	attributes := map[string]string{}
	for k, v := range user.Attributes {
		attributes[k] = strings.Join(v, MULTIVALUE_ATTRIBUTE_SEPARATOR)
	}

	data.SetId(fmt.Sprintf("%s/%s", user.RealmId, user.Id))
	data.Set("realm_id", user.RealmId)
	data.Set("service_account_user_id", user.Id)
	data.Set("username", user.Username)
	data.Set("email", user.Email)
	data.Set("email_verified", user.EmailVerified)
	data.Set("first_name", user.FirstName)
	data.Set("last_name", user.LastName)
	data.Set("enabled", user.Enabled)
	data.Set("attributes", attributes)
}

func resourceKeycloakOpenidClientServiceAccountUserCreate(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	keycloakClient := meta.(*keycloak.KeycloakClient)

	realmId := data.Get("realm_id").(string)
	serviceAccountUserId := data.Get("service_account_user_id").(string)

	existingUser, err := keycloakClient.GetUser(ctx, realmId, serviceAccountUserId)
	if err != nil {
		return diag.FromErr(err)
	}

	user := mapFromDataToServiceAccountUser(data)
	user.Username = existingUser.Username
	user.FederatedIdentities = existingUser.FederatedIdentities
	user.RequiredActions = existingUser.RequiredActions

	err = keycloakClient.UpdateUser(ctx, user)
	if err != nil {
		return diag.FromErr(err)
	}

	mapFromServiceAccountUserToData(data, user)

	return resourceKeycloakOpenidClientServiceAccountUserRead(ctx, data, meta)
}

func resourceKeycloakOpenidClientServiceAccountUserRead(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	keycloakClient := meta.(*keycloak.KeycloakClient)

	realmId := data.Get("realm_id").(string)
	serviceAccountUserId := data.Get("service_account_user_id").(string)

	user, err := keycloakClient.GetUser(ctx, realmId, serviceAccountUserId)
	if err != nil {
		return handleNotFoundError(ctx, err, data)
	}

	mapFromServiceAccountUserToData(data, user)

	return nil
}

func resourceKeycloakOpenidClientServiceAccountUserUpdate(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	keycloakClient := meta.(*keycloak.KeycloakClient)

	realmId := data.Get("realm_id").(string)
	serviceAccountUserId := data.Get("service_account_user_id").(string)

	existingUser, err := keycloakClient.GetUser(ctx, realmId, serviceAccountUserId)
	if err != nil {
		return diag.FromErr(err)
	}

	user := mapFromDataToServiceAccountUser(data)
	user.Username = existingUser.Username
	user.FederatedIdentities = existingUser.FederatedIdentities
	user.RequiredActions = existingUser.RequiredActions

	err = keycloakClient.UpdateUser(ctx, user)
	if err != nil {
		return diag.FromErr(err)
	}

	mapFromServiceAccountUserToData(data, user)

	return nil
}

func resourceKeycloakOpenidClientServiceAccountUserDelete(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	keycloakClient := meta.(*keycloak.KeycloakClient)

	realmId := data.Get("realm_id").(string)
	serviceAccountUserId := data.Get("service_account_user_id").(string)

	existingUser, err := keycloakClient.GetUser(ctx, realmId, serviceAccountUserId)
	if err != nil {
		if keycloak.ErrorIs404(err) {
			return nil
		}
		return diag.FromErr(err)
	}

	existingUser.Attributes = map[string][]string{}
	existingUser.Email = ""
	existingUser.EmailVerified = false
	existingUser.FirstName = ""
	existingUser.LastName = ""

	err = keycloakClient.UpdateUser(ctx, existingUser)
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func resourceKeycloakOpenidClientServiceAccountUserImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	keycloakClient := meta.(*keycloak.KeycloakClient)

	parts := strings.Split(d.Id(), "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("Invalid import. Supported import format: {{realmId}}/{{serviceAccountUserId}}")
	}

	realmId := parts[0]
	serviceAccountUserId := parts[1]

	user, err := keycloakClient.GetUser(ctx, realmId, serviceAccountUserId)
	if err != nil {
		return nil, err
	}

	d.Set("realm_id", realmId)
	d.Set("service_account_user_id", serviceAccountUserId)
	d.SetId(fmt.Sprintf("%s/%s", realmId, user.Id))

	diagnostics := resourceKeycloakOpenidClientServiceAccountUserRead(ctx, d, meta)
	if diagnostics.HasError() {
		return nil, fmt.Errorf("%s", diagnostics[0].Summary)
	}

	return []*schema.ResourceData{d}, nil
}
