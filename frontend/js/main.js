(function ($, Backbone, _) {
    var Heading = {
        Model: Backbone.Model.extend({
            defaults: {
                title:      undefined,
                content:    undefined,
            },
        }),

        View: Backbone.View.extend({
            initialize: function (options) {
                this.template = _.template(options.heading_content.html());
                this.model.on('change', this.render, this);
                this.render();
            },

            render: function () {
                this.$el.html(this.template({
                    head:       this.model.get('title'),
                    content:    this.model.get('content'),
                }));
            },

            show: function () {
                this.$el.removeClass("hide");
            },

            hide: function () {
                this.$el.addClass("hide");
            },
        }),
    };

    var Content = {
        Model: Backbone.Model.extend({}),
        View: Backbone.View.extend({
            initialize: function (options) {
                this.template = _.template(options.general_content.html());
                this.model.on('change', this.render, this);
                this.render();
            },

            render: function () {
                this.$el.html(this.template({}));
            },

            show: function () {
                this.$el.removeClass("hide");
            },

            hide: function () {
                this.$el.addClass("hide");
            },
        }),
    };

    var Login = {
        Model: Backbone.Model.extend({}),
        View: Backbone.View.extend({
            initialize: function (options) {
                this.template = _.template(options.login_form.html());
                this.model.on('change', this.render, this);
                this.$el.on('submit', 'form', this.apply, this);
            },

            render: function () {
                this.$el.html(this.template({}));
            },

            apply: function (form_ref) {
                var $form = $(form_ref),
                    login = $form.find("#login-login").val(),
                    passw = $form.find("#login-passw").val(),
                    remember = $form.find("#login-do_remember").prop("checked"),
                    class_name = "has-error",
                    $err = $form.find("#login-error_message");
                if (!login || !password)
                    $err.removeClass("hide");
                else
                    $err.addClass("hide");
                return false;
            },

            show: function () {
                this.render();
                this.$el.removeClass("hide");
                this.$el.find("#login-login").focus();
            },

            hide: function () {
                this.$el.addClass("hide");
            },
        }),
    };

    var MainRouter = Backbone.Router.extend({
        routes: {
            '':                 'index',
            'index':            'index',
            'login':            'login',
            'search/:query':    'search',
            'about':            'about',
        },

        initialize: function (options) {
            this._init_models(options.templates);
            this._init_views(options.templates);
        },

        _init_models: function (templates) {
            this.models = {
                heading: {
                    model:      new Heading.Model({
                        title:      'Hello',
                        content:    'Some content',
                    }),
                    el:         '.app-heading',
                    view_ref:   Heading.View,
                },

                general_content: {
                    model:      new Content.Model({}),
                    el:         '.app-content',
                    view_ref:   Content.View,
                },

                login_form: {
                    model:      new Login.Model({}),
                    el:         '.app-login_form',
                    view_ref:   Login.View,
                },
            };
        },

        _init_views: function (templates) {
            var key, val;
            for (key in this.models) {
                val = this.models[key];
                val.view = new val.view_ref(_.extend({
                    el:     val.el,
                    model:  val.model,
                }, templates));
            }
        },

        login: function () {
            this._hide(['login_form']);
        },

        search: function (query) {
            // TODO
        },

        index: function () {
            this._hide(['heading', 'general_content']);
        },

        _hide: function (exceptions) {
            var key, val;
            for (key in this.models) {
                var val = this.models[key];
                val.view[_.indexOf(exceptions, key) >= 0 ? "show" : "hide"]();
            }
        },
    });

    $(function () {
        var templates = {
            heading_content:    $('#src-heading_content'),
            general_content:    $('#src-general_content'),
            login_form:         $('#src-login_form'),
        };

        window.app = new MainRouter({
            templates: templates,
        });
        Backbone.history.start();
    });
}) ($, Backbone, _);
