from flask import Blueprint
import controllers.user_controller as user_ctrl
import controllers.dba_controller as dba_ctrl

# Create a blueprint, mapping the route to the controller function.
blueprint = Blueprint('blueprint', __name__)
blueprint.route('/create', methods=['GET','POST'])(dba_ctrl.create_account)
blueprint.route('/delete', methods=['GET','POST'])(dba_ctrl.delete_account)
blueprint.route('/login', methods=['GET','POST'])(user_ctrl.login)
blueprint.route('/logout', methods=['GET'])(user_ctrl.logout)
blueprint.route('/users', methods=['GET'])(user_ctrl.get_user_accounts)
blueprint.route('/infos', methods=['GET'])(user_ctrl.get_account_infos)
blueprint.route('/list', methods=['GET'])(dba_ctrl.list_users)
blueprint.route('/detail', methods=['GET', 'POST'])(dba_ctrl.detail_user)
blueprint.route('/update_privs_user', methods=['POST'])(dba_ctrl.update_privs_user)
blueprint.route('/lock_unlock_user/<string:astatus>/<string:username>', methods=['GET'])(dba_ctrl.lock_unlock_user)
blueprint.route('/list_profiles', methods=['GET'])(dba_ctrl.list_profiles)
blueprint.route('/detail_profile/<string:pf_name>', methods=['GET'])(dba_ctrl.detail_profile)
blueprint.route('/update_profile', methods=['POST'])(dba_ctrl.update_profile)

# This have POST for redirect from another post method
blueprint.route('/user_account_list', methods=['GET', 'POST'])(user_ctrl.user_account_list) 
# blueprint.route('/user_account_detail/<string:username>', methods=['GET'])(user_ctrl.user_account_detail)
# blueprint.route('/user_account_update', methods=['POST'])(user_ctrl.user_account_update)
blueprint.route('/user_account_delete/<int:userid>', methods=['GET'])(user_ctrl.user_account_delete)
blueprint.route('/user_account_create', methods=['GET', 'POST'])(user_ctrl.user_account_create)