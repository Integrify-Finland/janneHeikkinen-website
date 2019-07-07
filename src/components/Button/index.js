import React from 'react'
import classNames from 'classnames'
import './styles.scss'
import PropTypes from 'prop-types'

const Button = ({ variant, label, size, disabled, onClick }) => {
    const classes = classNames({
        button: true,
        'button--primary': variant === 'primary',
        'button--secondary': variant === 'secondary',
        'button--orange': variant === 'orange',
        'button--sm': size === 'sm',
        'button--md': size === 'md',
        'button--lg': size === 'lg',
    })

    return (
        <button 
        type="submit"
        className={classes}
        onClick={onClick}
        disabled={disabled}
        >
            {label}
        </button>
    
    )
}

export default Button;

Button.propTypes = {
    variant: PropTypes.oneOf(['primary', 'secondary', 'orange']),
    label: PropTypes.string.isRequired,
    size: PropTypes.oneOf(['sm', 'md', 'lg']).isRequired,
    disabled: PropTypes.bool,
    onClick: PropTypes.func
}

Button.defaultProps = {
    variant: '',
    disabled: false
}