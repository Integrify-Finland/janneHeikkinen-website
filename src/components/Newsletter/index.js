import React, { useState } from "react"
import classNames from "classnames"
import "./styles.scss"
import PropTypes from "prop-types"
import Button from "../Button"

const Newsletter = () => {
    
    const [animationStage, setAnimationStage] = useState("initial")

    if (animationStage === "initial") {
        return (
        <>
            <div className="newsletter-container">
            <Button
                variant="orange"
                size="lg"
                label="tilaa uutiskirje→"
                onClick={() => setAnimationStage("first stage")}
            />
            </div>
        </>
        )
    } else if (animationStage === "first stage") {
        return (
        <div className="newsletter-container">
            <div className="newsletter-container--first-stage">
                <p className="newsletter-container--first-stage__text-top">
                    Tilaa uutiskirje
                </p>
                <p className="newsletter-container--first-stage__text-bottom">
                    Sähköposti:
                </p>
                <input
                    className="newsletter-container--first-stage__input"
                    type="email"
                ></input>
                <Button
                    variant="primary"
                    size="md"
                    label="lähetä→"
                    onClick={() => setAnimationStage("second stage")}
                />
            </div>
        </div>
    )
    } else {
        return (
        <div className="newsletter-container ">
            <div className="newsletter-container--second-stage">
            <p className="newsletter-container--second-stage__invisible-text">
                Kiitos paljon!
            </p>
            </div>
        </div>
        )
    }
}

export default Newsletter
