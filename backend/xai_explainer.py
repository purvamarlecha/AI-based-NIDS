import shap


def explain_prediction(model, data, features, label_encoder):

    try:
        # Make sure feature order matches training
        data = data[features]

        # Create SHAP TreeExplainer
        explainer = shap.TreeExplainer(model)

        shap_values = explainer.shap_values(data)

        # Get prediction
        prediction = model.predict(data)[0]

        prediction_name = label_encoder.inverse_transform(
            [prediction]
        )[0]

        # Handle SHAP output
        if isinstance(shap_values, list):

            values = shap_values[prediction][0]

        else:

            values = shap_values

            if len(values.shape) == 3:
                values = values[0, :, prediction]

            elif len(values.shape) == 2:
                values = values[0]

        # Create explanation
        explanation = []

        for feature, value in zip(
            features,
            values
        ):

            explanation.append({
                "feature": feature,
                "impact": float(value),
                "absolute_impact": abs(float(value))
            })

        # Sort by importance
        explanation.sort(
            key=lambda x: x["absolute_impact"],
            reverse=True
        )

        # Return top 5
        return {
            "prediction": prediction_name,
            "top_features": explanation[:5]
        }

    except Exception as error:

        print(
            "XAI explanation error:",
            error
        )

        return {
            "prediction": "Unknown",
            "top_features": [],
            "error": str(error)
        }