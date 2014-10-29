/* passwdqc-plugin.c - 389-ds plugin for password strength
 * verification using passwdqc policy.
 *
 * Copyright (C) 2014 Juan Diego Campo
 * Unidad de Recursos Informáticos (URI)
 * Facultad de Ingeniería, Universidad de la República
 * Montevideo, Uruguay
 *
 * This Program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 of the
 * License.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <dirsrv/slapi-plugin.h>
#include <passwdqc.h>


/* ber tags for the PasswdModifyRequestValue sequence */
#define LDAP_EXTOP_PASSMOD_TAG_USERID	0x80U
#define LDAP_EXTOP_PASSMOD_TAG_OLDPWD	0x81U
#define LDAP_EXTOP_PASSMOD_TAG_NEWPWD	0x82U

/* OID of the extended operation handled by this plug-in */
#define EXTOP_PASSWD_OID "1.3.6.1.4.1.4203.1.11.1"

#define PASSWDQC_CONFIG_FILTER "(objectClass=*)"

static char *passwd_oid_list[] = {
  EXTOP_PASSWD_OID,
  NULL
};

static char *passwd_name_list[] = {
  "passwd_modify_extop",
  NULL
};

Slapi_PluginDesc passwdqc_desc = { "passwdqc",
				   "URI, Facultad de Ingeniería, Universidad de la república",
				   "0.1", "Plugin for password strength verification using passwdqc" };

static passwdqc_params_t config;
static Slapi_RWLock *passwdqc_config_lock = 0;
static int inited = 0;

static Slapi_DN* _pluginDN = NULL;
static void* _PluginID = NULL;


void
passwdqc_set_plugin_area (Slapi_DN *sdn)
{
  slapi_sdn_free (&_pluginDN);
  _pluginDN = slapi_sdn_dup (sdn);
}

Slapi_DN *
passwdqc_get_plugin_area ()
{
  return _pluginDN;
}

void passwdqc_set_plugin_id(void * plugin_id) 
{
	_PluginID=plugin_id;
}

void * passwdqc_get_plugin_id()
{
	return _PluginID;
}


static int
dont_allow_that (Slapi_PBlock *pb, Slapi_Entry* entryBefore, Slapi_Entry* e, 
		 int *returncode, char *returntext, void *arg)
{
  *returncode = LDAP_UNWILLING_TO_PERFORM;
  return SLAPI_DSE_CALLBACK_ERROR;
}


void
passwdqc_rlock_config ()
{
  slapi_rwlock_rdlock (passwdqc_config_lock);
}

/*
 * passwdqc_wlock_config ()
 * 
 * Gets an exclusive lock on the main config. This should be called if
 * you need to write to the main config.
 */
void
passwdqc_wlock_config ()
{
  slapi_rwlock_wrlock (passwdqc_config_lock);
}

/*
 * passwdqc_unlock_config ()
 *
 * Unlocks the main config.
 */
void
passwdqc_unlock_config ()
{
  slapi_rwlock_unlock (passwdqc_config_lock);
}

static int
passwdqc_search (Slapi_PBlock *pb, Slapi_Entry* entryBefore, Slapi_Entry* e, 
		 int *returncode, char *returntext, void *arg)
{
  return SLAPI_DSE_CALLBACK_OK;
}


/*
 * passwdqc_apply_config ()
 *
 * Apply the pending changes in the e entry to passwdqc config struct.
 */
int
passwdqc_apply_config (Slapi_PBlock *pb, Slapi_Entry* entryBefore, Slapi_Entry* e, 
		       int *returncode, char *returntext, void *arg)
{
  char **passwdqc_param_attr = NULL;
  int num_passwdqc_param_attrs = 0;
  char *parse_reason;

  *returncode = LDAP_SUCCESS;

  passwdqc_param_attr = slapi_entry_attr_get_charray(e, "passwdqcParam");

  /* Count the number of passwdqc param attrs. */
  num_passwdqc_param_attrs = 0;
  while (passwdqc_param_attr && passwdqc_param_attr[num_passwdqc_param_attrs])
    {
      num_passwdqc_param_attrs++;
    }

  /* We want to be sure we don't change the config in the middle of
   * a passwdqc operation, so we obtain an exclusive lock here */
  passwdqc_wlock_config ();

  passwdqc_params_reset(&config); /* set default values */
  if (passwdqc_params_parse (&config, &parse_reason, num_passwdqc_param_attrs, (const char* const *)passwdqc_param_attr))
    {
      slapi_log_error (SLAPI_LOG_FATAL, "passwdqc",
		       "Error parsing configuration: %s\n", parse_reason);
      *returncode = LDAP_UNWILLING_TO_PERFORM;
    }
  /* release the lock */
  passwdqc_unlock_config ();

  slapi_ch_array_free (passwdqc_param_attr);

  if (*returncode != LDAP_SUCCESS)
    return SLAPI_DSE_CALLBACK_ERROR;
  else
    return SLAPI_DSE_CALLBACK_OK;
}


/*
 * passwdqc_config ()
 * 
 * Read configuration and create a configuration data structure.
 */
int
passwdqc_config (Slapi_Entry *config_e, Slapi_PBlock *pb)
{
  int rc = LDAP_SUCCESS;
  char returntext[SLAPI_DSE_RETURNTEXT_SIZE];

  if (inited)
    {
      slapi_log_error (SLAPI_LOG_FATAL, "passwdqc",
		       "only one passwdqc plugin instance can be used\n");
      return (LDAP_PARAM_ERROR);
    }

  passwdqc_config_lock = slapi_new_rwlock ();

  /* Apply config into passwdqc struct */
  passwdqc_apply_config (NULL, NULL, config_e, &rc, returntext, NULL);

  /* Set up callbacks for the config entry */
  const char *config_dn = slapi_sdn_get_dn (passwdqc_get_plugin_area());
  slapi_config_register_callback (SLAPI_OPERATION_MODIFY, DSE_FLAG_PREOP,
				  config_dn, LDAP_SCOPE_BASE, PASSWDQC_CONFIG_FILTER,
				  passwdqc_apply_config,NULL);
  slapi_config_register_callback (SLAPI_OPERATION_MODRDN, DSE_FLAG_PREOP,
				  config_dn, LDAP_SCOPE_BASE, PASSWDQC_CONFIG_FILTER,
				  dont_allow_that, NULL);
  slapi_config_register_callback (SLAPI_OPERATION_DELETE, DSE_FLAG_PREOP,
				  config_dn, LDAP_SCOPE_BASE, PASSWDQC_CONFIG_FILTER,
				  dont_allow_that, NULL);
  slapi_config_register_callback (SLAPI_OPERATION_SEARCH, DSE_FLAG_PREOP,
				  config_dn, LDAP_SCOPE_BASE, PASSWDQC_CONFIG_FILTER,
				  passwdqc_search,NULL);
  inited = 1;

  if (rc != LDAP_SUCCESS)
    {
      slapi_log_error (SLAPI_LOG_FATAL, "passwdqc",
		       "Error %d: %s\n", rc, returntext);
    }

  return rc;
}


/*
 * passwdqc_start ()
 *
 * Function called on server startup. Loads configuration from plugin
 * entry.
 *
 */
int
passwdqc_start (Slapi_PBlock *pb)
{
  Slapi_Entry *config_e = NULL; /* entry containing plugin config */
  int rc = 0;

  slapi_log_error (SLAPI_LOG_PLUGIN, "passwdqc",
		   "--> passwqc_extop_start\n");

  if (slapi_pblock_get (pb, SLAPI_ADD_ENTRY, &config_e) != 0 )
    rc = -1;
  else
    {
      passwdqc_set_plugin_area(slapi_entry_get_sdn(config_e));
      if ((rc = passwdqc_config (config_e, pb)) != LDAP_SUCCESS)
	{
	  slapi_log_error (SLAPI_LOG_FATAL, "passwdqc",
			   "configuration failed (%s)\n", ldap_err2string (rc));
	  rc = -1;
	}
    }

  slapi_log_error( SLAPI_LOG_PLUGIN, "passwdqc",
		   "<-- passwdqc_start\n" );

  return rc;
}


/*
 * passwdqc_get_user_passwd ()
 *
 * Returns the passwd entry of the user pointed by dn. Returns NULL if
 * user cannot be found. Returned memory should be freed by the caller.
 *
 */
struct passwd *
passwdqc_get_user_passwd (char *dn)
{
  Slapi_DN      *sdn = NULL;
  Slapi_Entry   *user_entry = NULL;
  char          *attr = NULL;
  char          *firstName = NULL;
  char          *sn = NULL;
  struct passwd *user_pw = NULL;

  /* Search for the user entry */
  sdn = slapi_sdn_new_dn_byval(dn);
  if (sdn)
    {
      slapi_search_internal_get_entry (sdn, NULL, &user_entry, passwdqc_get_plugin_id());
      slapi_sdn_free(&sdn);
    }
  if (!user_entry)
    return NULL;


  user_pw = malloc (sizeof (struct passwd));

  /* Get uid */
  attr = slapi_entry_attr_get_charptr (user_entry, "uid");
  user_pw->pw_name = attr ? attr : slapi_ch_strdup("");

  user_pw->pw_passwd = slapi_ch_strdup("*");

  /* Get uidNumber */
  user_pw->pw_uid = slapi_entry_attr_get_int (user_entry, "uidNumber");

  /* Get gidNumber */
  user_pw->pw_gid = slapi_entry_attr_get_int (user_entry, "gidNumber");

  /* Get homedir */
  attr = slapi_entry_attr_get_charptr (user_entry, "homeDirectory");
  user_pw->pw_dir = attr ? attr : slapi_ch_strdup("");

  /* Get shell */
  attr = slapi_entry_attr_get_charptr (user_entry, "loginShell");
  user_pw->pw_shell = attr ? attr : slapi_ch_strdup("");

  /* Get full name (gecos, cn, firstName + sn, or uid, in that order. */
  attr = slapi_entry_attr_get_charptr (user_entry, "gecos");
  if (!attr)
    {
      attr = slapi_entry_attr_get_charptr (user_entry, "cn");
      if (!attr)
	{
	  firstName = slapi_entry_attr_get_charptr (user_entry, "firstName");
	  sn = slapi_entry_attr_get_charptr (user_entry, "sn");
	  if (firstName && sn)
	    attr = slapi_ch_smprintf("%s %s", firstName, sn);
	  else if (sn)
	    attr = slapi_ch_strdup(sn);
	  else if (firstName)
	    attr = slapi_ch_strdup(firstName);
	  else
	    attr = slapi_ch_strdup(user_pw->pw_name);
	}
    }
  user_pw->pw_gecos = attr ? attr : slapi_ch_strdup("");


  slapi_entry_free (user_entry);
  slapi_ch_free_string (&firstName);
  slapi_ch_free_string (&sn);
 
  return user_pw;
}

/*
 * passwdqc_change_pass ()
 *
 * Check password against configured policy before change.
 *
 */
int
passwdqc_change_pass (Slapi_PBlock *pb)
{
  char 		*bindDN = NULL;
  char		*authmethod = NULL;
  char		*dn = NULL;
  char		*oldPasswd = NULL;
  char		*newPasswd = NULL;
  struct passwd *user_pw = NULL;
  char		*errMesg = NULL;
  int           rc=0;
  ber_tag_t	tag=0;
  ber_len_t	len=-1;
  struct berval	*extop_value = NULL;
  BerElement	*ber = NULL;

  /* Get the ber value of the extended operation */
  slapi_pblock_get(pb, SLAPI_EXT_OP_REQ_VALUE, &extop_value);

  if ((ber = ber_init (extop_value)) == NULL)
    {
      errMesg = "PasswdModify Request decode failed.\n";
      rc = LDAP_PROTOCOL_ERROR;
      goto free_and_return;
    }

  /* Format of request to parse
   *
   * PasswdModifyRequestValue ::= SEQUENCE {
   * userIdentity    [0]  OCTET STRING OPTIONAL
   * oldPasswd       [1]  OCTET STRING OPTIONAL
   * newPasswd       [2]  OCTET STRING OPTIONAL }
   *
   * The request value field is optional. If it is
   * provided, at least one field must be filled in.
   */

  /* ber parse code */
  if ( ber_scanf( ber, "{") == LBER_ERROR )
    {
      errMesg = "Missing values\n";
      rc = LDAP_UNWILLING_TO_PERFORM;
      goto free_and_return;
    }
  else
    {
      tag = ber_peek_tag (ber, &len);
    }

  /* identify userID field by tags */
  if (tag == LDAP_EXTOP_PASSMOD_TAG_USERID )
    {
      if (ber_scanf (ber, "a", &dn) == LBER_ERROR)
	{
	  slapi_ch_free_string(&dn);
	  errMesg = "ber_scanf failed at userID parse.\n";
	  rc = LDAP_PROTOCOL_ERROR;
	  goto free_and_return;
	}

      tag = ber_peek_tag(ber, &len);
    }

  /* identify oldPasswd field by tags */
  if (tag == LDAP_EXTOP_PASSMOD_TAG_OLDPWD )
    {
      if (ber_scanf (ber, "a", &oldPasswd) == LBER_ERROR)
	{
	  errMesg = "ber_scanf failed at oldPasswd parse.\n";
	  rc = LDAP_PROTOCOL_ERROR;
	  goto free_and_return;
	}
      tag = ber_peek_tag (ber, &len);
    }

  /* identify newPasswd field by tags */
  if (tag == LDAP_EXTOP_PASSMOD_TAG_NEWPWD )
    {
      if (ber_scanf (ber, "a", &newPasswd) == LBER_ERROR)
	{
	  errMesg = "ber_scanf failed at newPasswd parse.\n";
	  rc = LDAP_PROTOCOL_ERROR;
	  goto free_and_return;
	}
    }

  /* Uncomment for debugging, otherwise we don't want to leak the
   * password values into the log... */
  /* slapi_log_error (SLAPI_LOG_PLUGIN, "passwdqc", */
  /* 		   "passwd: dn (%s), oldPasswd (%s), newPasswd (%s)\n", */
  /* 		   dn, oldPasswd, newPasswd); */

  /* Get Bind DN */
  slapi_pblock_get (pb, SLAPI_CONN_DN, &bindDN);

  /* If the connection is bound anonymously, we must refuse
   * to process this operation. */
  if (bindDN == NULL || *bindDN == '\0') {
    /* Refuse the operation because they're bound anonymously */
    errMesg = "Anonymous Binds are not allowed.\n";
    rc = LDAP_INSUFFICIENT_ACCESS;
    goto free_and_return;
  }

  /* A new password was not supplied in the request.
   */
  if (newPasswd == NULL || *newPasswd == '\0') {
    errMesg = "New password not supplied\n";
    rc = LDAP_UNWILLING_TO_PERFORM;
    goto free_and_return;
  }

  if (oldPasswd == NULL || *oldPasswd == '\0') {
    /* If user is authenticated, they already gave their password during
       the bind operation (or used sasl or client cert auth or OS creds) */
    slapi_pblock_get (pb, SLAPI_CONN_AUTHMETHOD, &authmethod);
    if (!authmethod || !strcmp(authmethod, SLAPD_AUTH_NONE)) {
      errMesg = "User must be authenticated to the directory server.\n";
      rc = LDAP_INSUFFICIENT_ACCESS;
      goto free_and_return;
    }
  }

  /* Determine the target DN for this operation */
  /* Did they give us a DN ? */
  if (dn == NULL || *dn == '\0') {
    errMesg = "DN not supplied\n";
    rc = LDAP_UNWILLING_TO_PERFORM;
    goto free_and_return;
  }

  user_pw = passwdqc_get_user_passwd (dn);
  
  char *check_reason;

  passwdqc_rlock_config();
  check_reason = (char*)passwdqc_check(&config.qc, newPasswd, oldPasswd, user_pw);
  passwdqc_unlock_config();
  
  if (check_reason)
    {
      errMesg = check_reason;
      rc = LDAP_UNWILLING_TO_PERFORM;
    }
  else
    {
      rc = LDAP_SUCCESS;
    }


  /* Free anything that we allocated above */
 free_and_return:
  slapi_ch_free_string (&oldPasswd);
  slapi_ch_free_string (&newPasswd);
  slapi_ch_free_string (&dn);
  slapi_ch_free_string (&authmethod);

  if (user_pw)
    {
      slapi_ch_free_string (&user_pw->pw_name);
      slapi_ch_free_string (&user_pw->pw_passwd);
      slapi_ch_free_string (&user_pw->pw_gecos);
      slapi_ch_free_string (&user_pw->pw_dir);
      slapi_ch_free_string (&user_pw->pw_shell);
      free (user_pw);
    }

  if (ber) ber_free(ber, 1);

  slapi_log_error (SLAPI_LOG_PLUGIN, "passwdqc",
		   "%s", errMesg ? errMesg : "success");

  if (rc != LDAP_SUCCESS)
    {
      slapi_send_ldap_result(pb, rc, NULL, errMesg, 0, NULL);
      return SLAPI_PLUGIN_EXTENDED_SENT_RESULT;
    }
  else
    return LDAP_SUCCESS;
}



/*
 * passwdqc_modify_entry ()
 *
 * Check if changed attribute is userPassword. If it is plain text,
 * check policy. If not, fail. Unless the modification is done by a
 * user with read/write permissions on the user password attribute.
 *
 */
int
passwdqc_modify_entry (Slapi_PBlock *pb)
{
  int rc = LDAP_SUCCESS;
  char *errMesg = NULL;
  char *check_reason = NULL;
  char *dn = NULL;
  struct passwd *user_pw = NULL;
  LDAPMod **mods;
  LDAPMod *mod;
  char *new_password = NULL;
  char *new_unhashed_password = NULL;
  Slapi_Entry *user_entry = NULL;
  
  /* Get the target DN */
  if (slapi_pblock_get(pb, SLAPI_MODIFY_TARGET, &dn) || !dn)
    {
      errMesg = "Internal error getting the dn";
      rc = LDAP_UNWILLING_TO_PERFORM;
      goto free_and_return;
    }

  /* Search for the user entry */
  Slapi_DN *sdn = slapi_sdn_new_dn_byval(dn);
  if (sdn)
    {
      slapi_search_internal_get_entry (sdn, NULL, &user_entry, passwdqc_get_plugin_id());
      slapi_sdn_free(&sdn);
    }
  
  if (slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &mods))
    {
      errMesg = "Internal error parsing modifications";
      rc = LDAP_UNWILLING_TO_PERFORM;
      goto free_and_return;
    }

    /* find out how many mods meet this criteria */
    for(;*mods;mods++)
      {
        mod = *mods;
        if ((slapi_attr_type_cmp(mod->mod_type, "unhashed#user#password", 1) == 0) &&
	    (mod->mod_bvalues && mod->mod_bvalues[0]) &&
            (SLAPI_IS_MOD_ADD(mod->mod_op) ||
             SLAPI_IS_MOD_REPLACE(mod->mod_op)))
        {
	  new_unhashed_password = slapi_ch_malloc (mod->mod_bvalues[0]->bv_len + 1);
	  sprintf (new_unhashed_password, "%.*s", (int)mod->mod_bvalues[0]->bv_len,
		   mod->mod_bvalues[0]->bv_val);

        } else if ((slapi_attr_type_cmp(mod->mod_type, "userPassword", 1) == 0) &&
		   (mod->mod_bvalues && mod->mod_bvalues[0]) &&
		   (SLAPI_IS_MOD_ADD(mod->mod_op) ||
		    SLAPI_IS_MOD_REPLACE(mod->mod_op)))
        {
	  new_password = slapi_ch_malloc (mod->mod_bvalues[0]->bv_len + 1);
	  sprintf (new_password, "%.*s", (int)mod->mod_bvalues[0]->bv_len,
		   mod->mod_bvalues[0]->bv_val);
        }
      }

    
    struct berval val = { new_password ? strlen(new_password) : 0, new_password };
    
    if (!new_password && !new_unhashed_password)
      {
	goto free_and_return;
      }
    else if (user_entry && (slapi_access_allowed (pb, user_entry, "userPassword", &val, SLAPI_ACL_READ) == LDAP_SUCCESS))
      {
	/* If user can read the userPassword attribute, assume the
	   modifier is an admin, so proceed without checking. */
	goto free_and_return;
      }
    else if (slapi_is_encoded(new_password)) 
      {
	if (!new_unhashed_password || slapi_is_encoded(new_unhashed_password))
	  {
	    /* User provided the hash, just fail */
	    errMesg = "Hashed password modification is not allowed";
	    rc = SLAPI_PLUGIN_EXTENDED_SENT_RESULT;
	    goto free_and_return;
	  }
	else
	  {
	    slapi_ch_free_string (&new_password);
	    new_password = slapi_ch_strdup (new_unhashed_password);
	  }
      }
    /* slapi_log_error (SLAPI_LOG_FATAL, "passwdqc_modify_entry", */
    /* 		     "New password: %s\n", new_password); */


    user_pw = passwdqc_get_user_passwd (dn);
    passwdqc_rlock_config();
    check_reason = (char*)passwdqc_check(&config.qc, new_password, "", user_pw);
    passwdqc_unlock_config(); 
    if (check_reason)
      {
	errMesg = check_reason;
	rc = LDAP_UNWILLING_TO_PERFORM;
	goto free_and_return;
      }

free_and_return:
    slapi_ch_free_string(&new_password);
    slapi_ch_free_string(&new_unhashed_password);

    if (user_pw)
      {
	slapi_ch_free_string (&user_pw->pw_name);
	slapi_ch_free_string (&user_pw->pw_passwd);
	slapi_ch_free_string (&user_pw->pw_gecos);
	slapi_ch_free_string (&user_pw->pw_dir);
	slapi_ch_free_string (&user_pw->pw_shell);
	free (user_pw);
      }

    if (rc != LDAP_SUCCESS)
      {
	slapi_log_error(SLAPI_LOG_PLUGIN, "passwdqc_modify_entry",
			"%s\n", errMesg);
	slapi_send_ldap_result(pb, rc, NULL, errMesg, 0, NULL);
	return SLAPI_PLUGIN_EXTENDED_SENT_RESULT;
      }
    else
      {
	return LDAP_SUCCESS;
      }
}

/* Extop initialization function */
int
passwdqc_extop_init (Slapi_PBlock *pb)
{
  if (slapi_pblock_set (pb, SLAPI_PLUGIN_EXT_OP_FN, (void *) passwdqc_change_pass) != 0 ||
      slapi_pblock_set (pb, SLAPI_PLUGIN_EXT_OP_OIDLIST, passwd_oid_list ) != 0 ||
      slapi_pblock_set (pb, SLAPI_PLUGIN_EXT_OP_NAMELIST, passwd_name_list ) != 0)
    {
      slapi_log_error (SLAPI_LOG_FATAL, "passwdqc",
		       "Failed to set plug-in version, function, and OID.\n");
      return -1;
    }
}

/* Initialization function */
int
passwdqc_init (Slapi_PBlock *pb)

/* This function is called when the plug-in shared object is first
   loaded into memory, usually at server start up time. This function
   name must be specified in the plug-in configuration entry under
   cn=plugins,cn=config. This function should not do very much, mostly
   just set the operation specific callback functions. The rest of the
   configuration should be done in the start function when the plug-in
   has access to the plug-in entry (which should have all of the
   plug-in configuration information). */

{
  char *passwdqc_plugin_identity = NULL;

  passwdqc_params_reset(&config); /* set default values */

  slapi_pblock_get (pb, SLAPI_PLUGIN_IDENTITY, &passwdqc_plugin_identity);
  passwdqc_set_plugin_id(passwdqc_plugin_identity);

  /* Register the plug-in function as an extended operation plug-in
   * function that handles the operation identified by OID
   * 1.3.6.1.4.1.4203.1.11.1 . Also specify the version of the server
   * plug-in */
  if  (slapi_pblock_set (pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01 ) != 0 ||
       slapi_pblock_set (pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&passwdqc_desc) != 0 ||

       slapi_pblock_set (pb, SLAPI_PLUGIN_START_FN, (void *) passwdqc_start ) != 0 ||

       slapi_pblock_set (pb, SLAPI_PLUGIN_PRE_MODIFY_FN, (void *) passwdqc_modify_entry) != 0)
    {
      slapi_log_error (SLAPI_LOG_FATAL, "passwdqc",
		       "Failed to set plug-in version, function, and OID.\n");
      return -1;
    }

  /* Register extended operation functions */
  if (slapi_register_plugin("extendedop", 1, "passwdqc_init", passwdqc_extop_init,
			    "passwdqc extop plugin", NULL, passwdqc_plugin_identity))
    {
      slapi_log_error (SLAPI_LOG_FATAL, "passwdqc",
		       "Failed to set plug-in version, function, and OID.\n");
      return -1;
    }      

  return 0;
}
