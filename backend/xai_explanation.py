import shap


def explain_prediction(model, data, attack_name):

    try:

        # --------------------------------------
        # Get model prediction first
        # --------------------------------------

        prediction = model.predict(data)[0]


        # --------------------------------------
        # Create SHAP explainer
        # --------------------------------------

        explainer = shap.TreeExplainer(model)

        shap_values = explainer.shap_values(data)


        # --------------------------------------
        # Handle SHAP output
        # --------------------------------------

        if isinstance(shap_values, list):

            # For older SHAP versions
            values = shap_values[prediction][0]

        else:

            # For newer SHAP versions
            values = shap_values

            if len(values.shape) == 3:

                values = values[0, :, prediction]

            elif len(values.shape) == 2:

                values = values[0]


        # --------------------------------------
        # Feature names
        # --------------------------------------

        feature_names = data.columns.tolist()


        # --------------------------------------
        # Match feature values
        # --------------------------------------

        feature_importance = list(
            zip(
                feature_names,
                values
            )
        )


        # --------------------------------------
        # Sort by importance
        # --------------------------------------

        feature_importance.sort(
            key=lambda x: abs(x[1]),
            reverse=True
        )


        # --------------------------------------
        # Top 3 features
        # --------------------------------------

        top_features = feature_importance[:3]


        # --------------------------------------
        # Display explanation
        # --------------------------------------

        print("\n------------------------------------------")
        print("        EXPLAINABLE AI ANALYSIS")
        print("------------------------------------------")

        print(
            "Detected Activity:",
            attack_name
        )

        print(
            "\nMain factors influencing prediction:"
        )


        for feature, value in top_features:

            if value > 0:

                effect = "increased"

            else:

                effect = "reduced"


            print(
                f"- {feature}: "
                f"{effect} the prediction "
                f"({abs(value):.4f})"
            )


        return top_features


    except Exception as error:

        print(
            "\nXAI explanation unavailable:",
            error
        )

        return []