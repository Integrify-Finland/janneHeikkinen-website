import React from 'react'
import PropTypes from 'prop-types'
import classNames from 'classnames'
import './styles.scss'

const ColumnsGrid = ({ children, columns = 0 }) => {
  const grid = classNames({
    'grid-container': true,
    [`grid-container--${columns}`]: columns,
  })
  return <div className={grid}>{children}</div>
}

ColumnsGrid.propTypes = {
  children: PropTypes.node.isRequired,
  columns: PropTypes.number,
}

ColumnsGrid.defaultProps = {
  columns: 0,
}

export default ColumnsGrid
