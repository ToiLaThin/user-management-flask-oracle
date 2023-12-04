from flask import Blueprint
import controllers.user_controller as ctrl

# Create a blueprint, mapping the route to the controller function.
blueprint = Blueprint('blueprint', __name__)
blueprint.route('/create', methods=['GET'])(ctrl.create_account)