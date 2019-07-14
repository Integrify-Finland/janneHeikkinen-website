import React from "react"
import PropTypes from "prop-types"

import "./styles.scss"

const Pagination = ({ postsPerPage, totalPosts, paginate, currentPage }) => {
  const pageNumbers = []

  for (let i = 1; i <= Math.ceil(totalPosts / postsPerPage); i++) {
    pageNumbers.push(i)
  }

  return (
    <nav>
      <ul className="pagination">
        {pageNumbers.map(number => (
          <li
            key={number}
            className={`${
              currentPage === number
                ? "pagination__numbers--active"
                : "pagination__numbers"
            }`}
            onClick={() => paginate(number)}
          >
            <span>{number}</span>
          </li>
        ))}
      </ul>
    </nav>
  )
}

export default Pagination

Pagination.propTypes = {
  totalPosts: PropTypes.number.isRequired,
  postsPerPage: PropTypes.number.isRequired,
  currentPage: PropTypes.number.isRequired,
  Pagination: PropTypes.func.isRequired,
}
