from flask import Blueprint
import controllers.user_controller as user_ctrl
import controllers.dba_controller as dba_ctrl

# Create a blueprint, mapping the route to the controller function.
blueprint = Blueprint('blueprint', __name__)

blueprint.route('/', methods=['GET'])(user_ctrl.index)

blueprint.route('/create', methods=['GET','POST'])(dba_ctrl.create_account)
blueprint.route('/delete/<string:username>', methods=['GET'])(dba_ctrl.delete_account)
blueprint.route('/login', methods=['GET','POST'])(user_ctrl.login)
blueprint.route('/logout', methods=['GET'])(user_ctrl.logout)

blueprint.route('/infos', methods=['GET'])(user_ctrl.get_account_infos)

blueprint.route('/list', methods=['GET'])(dba_ctrl.list_users)
blueprint.route('/detail', methods=['GET', 'POST'])(dba_ctrl.detail_user)
blueprint.route('/update_privs_user', methods=['POST'])(dba_ctrl.update_privs_user)
blueprint.route('/lock_unlock_user/<string:astatus>/<string:username>', methods=['GET'])(dba_ctrl.lock_unlock_user)

blueprint.route('/list_profiles', methods=['GET'])(dba_ctrl.list_profiles)
blueprint.route('/detail_profile/<string:pf_name>', methods=['GET'])(dba_ctrl.detail_profile)
blueprint.route('/update_profile', methods=['POST'])(dba_ctrl.update_profile)


blueprint.route('/roles/<string:selected_role>', methods=['GET'])(dba_ctrl.get_role_info)
blueprint.route('/roles', methods=['GET'])(dba_ctrl.get_all_roles)
blueprint.route('/update_privs_role', methods=['POST'])(dba_ctrl.update_privs_role)
blueprint.route('/update_user_role', methods=['GET', 'POST'])(dba_ctrl.update_user_role)
blueprint.route('/enable_role_pwd', methods=['POST'])(dba_ctrl.enable_role_pwd)
blueprint.route('/disable_or_update_role_pwd', methods=['POST'])(dba_ctrl.disable_or_update_role_pwd)


# This have POST for redirect from another post method
blueprint.route('/user_account_list', methods=['GET', 'POST'])(user_ctrl.user_account_list) 
blueprint.route('/user_account_delete/<int:userid>', methods=['GET'])(user_ctrl.user_account_delete)
blueprint.route('/user_account_create', methods=['GET', 'POST'])(user_ctrl.user_account_create)

blueprint.route('/grant_privs_user_list', methods=['GET'])(user_ctrl.grant_privs_user_list)
blueprint.route('/grant_priv_user_detail/<string:grantor>/<string:grantee>', methods=['GET'])(user_ctrl.grant_priv_user_detail)
blueprint.route('/grant_priv_user_update', methods=['POST'])(user_ctrl.grant_priv_user_update)

# set role for session
blueprint.route('/disable_session_role', methods=['POST'])(user_ctrl.disable_session_role)
blueprint.route('/enable_session_role', methods=['POST'])(user_ctrl.enable_session_role)
blueprint.route('/enable_session_role_with_password', methods=['POST'])(user_ctrl.enable_session_role_with_password)