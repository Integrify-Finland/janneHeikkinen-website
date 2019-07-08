import React, { useState } from 'react'
import classNames from 'classnames'
import './styles.scss'
import PropTypes from 'prop-types'
import Button from '../Button'

const Newsletter = () => {

    const [animationStage, setAnimationStage] = useState('first stage')
    
    // function toggle() {
    //     animated ? setAnimated(true) : setAnimated(false)
    // }

    if (animationStage === 'first stage') {
        return (    
            <div className="newsletter-container">
                <p className="newsletter-container__text-top">Tilaa uutiskirje</p>
                <p className="newsletter-container__text-bottom">Sähköposti:</p>
                <input className="newsletter-container__input" type="email"></input>
                <Button 
                variant="primary"
                size="md"
                label="lähetä→"
                onClick={() => setAnimationStage('second stage')}
                />
                <p className="newsletter-container__invisible-text">Kiitos paljon!</p> 
            </div>
        )
    } else {
        return (
            <div className="newsletter-container__animated">
                <p className="newsletter-container__animated__text-top">Tilaa uutiskirje</p>
                <p className="newsletter-container__animated__text-bottom">Sähköposti:</p>
                <input className="newsletter-container__animated__input" type="email"></input>
                {/* <Button 
                variant="primary"
                size="md"
                label="lähetä→"
                onClick={toggle}
                /> */}
                <p className="newsletter-container__animated__invisible-text">Kiitos paljon!</p>
            </div>
        )
    }
}



//     return (

//         <div className="newsletter-container">
//             <p className="newsletter-container__text-top">Tilaa uutiskirje</p>
//             <p className="newsletter-container__text-bottom">Sähköposti:</p>
//             <input className="newsletter-container__input" type="email"></input>
//             <Button 
//             variant="primary"
//             size="md"
//             label="lähetä→"
//             />
//             <p className="newsletter-container__invisible-text">Kiitos paljon!</p>
//         </div>
    
//     )
// }

export default Newsletter;
