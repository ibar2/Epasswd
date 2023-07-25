class auth:
    """
    A router to control all database operations on models in the
    auth and contenttypes applications.
    """

    route_app_labels = {"auth", "sessions", "admin", "contenttypes"}

    def db_for_read(self, model, **hints):
        """
        Attempts to read auth and contenttypes models go to db1.
        """
        if model._meta.app_label in self.route_app_labels:
            return "db1"
        return None

    def db_for_write(self, model, **hints):
        """
        Attempts to write auth and contenttypes models go to db1.
        """
        if model._meta.app_label in self.route_app_labels:
            return "db1"
        return None

    def allow_relation(self, obj1, obj2, **hints):
        """
        Allow relations if a model in the auth or contenttypes apps is
        involved.
        """
        if (
            obj1._meta.app_label in self.route_app_labels
            or obj2._meta.app_label in self.route_app_labels
        ):
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        Make sure the auth and contenttypes apps only appear in the
        'db1' database.
        """
        if app_label in self.route_app_labels:
            return db == "db1"
        return None


class routemodel:
    """
    A router to control database operations on models in the epasswd_app app.
    """

    route_models = {"user", "passwords", 'partialpassword', 'hashers'}

    def db_for_read(self, model, **hints):
        """
        Attempts to read models go to their respective databases.
        """
        if model._meta.model_name in self.route_models:
            if model._meta.model_name == "user" or model._meta.model_name == 'partialpass':
                return 'db1'
            else:
                return 'db2'
        return None

    def db_for_write(self, model, **hints):
        """
        Attempts to write models go to their respective databases.
        """
        if model._meta.model_name in self.route_models:
            if model._meta.model_name == "user" or model._meta.model_name == 'partialpass':
                return 'db1'
            else:
                return 'db2'
        return None

    def allow_relation(self, obj1, obj2, **hints):
        """
        Allow relations if models in the app are involved.
        """
        if (
            obj1._meta.app_label == "page" or
            obj2._meta.app_label == "page"
        ):
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        Make sure models only appear in their respective databases.
        """
        if app_label == "page" and model_name in self.route_models:
            if model_name == "user" or model_name == 'partialpass':
                return 'db1'
            else:
                return 'db2'
        return None
