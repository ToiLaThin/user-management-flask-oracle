from flask import Blueprint
import controllers.user_controller as ctrl

# Create a blueprint, mapping the route to the controller function.
blueprint = Blueprint('blueprint', __name__)
blueprint.route('/create', methods=['GET','POST'])(ctrl.create_account)
blueprint.route('/delete', methods=['GET','POST'])(ctrl.delete_account)
blueprint.route('/login', methods=['GET','POST'])(ctrl.login)
blueprint.route('/logout', methods=['GET'])(ctrl.logout)
blueprint.route('/users', methods=['GET'])(ctrl.get_user_accounts)
blueprint.route('/infos', methods=['GET'])(ctrl.get_account_infos)