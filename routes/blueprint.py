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