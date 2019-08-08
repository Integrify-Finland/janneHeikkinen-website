import React from "react"
import BlogItem from "../BlogItem"

import "./styles.scss"

const Sidebar = ({
  renderBlogs,
  blogs,
  image,
  shortText,
  categories,
  tags,
}) => {
  return (
    <aside className="blogs-sidebar">
      <div className="blogs-sidebar__blogs">
        <h3>Recommended blogs:</h3>
        {blogs.slice(0, 3).map(({ node, number }) => (
          <BlogItem
            isSidebar
            date="5.6.2018"
            title={node.title}
            number={number}
            image={image}
            text={shortText}
            link={`blogi/${node.slug
              .toLowerCase()
              .replace(/[']/gi, "")
              .replace(/ /gi, "-")
              .replace(/[,]/gi, "")
              .replace(/[ä]/gi, "a")
              .replace(/[ö]/gi, "o")}`}
          />
        ))}
      </div>
      <div className="blogs-sidebar__categories">
        <h3>Categories:</h3>
        <ul>
          {categories.map(cat => (
            <li onClick={() => renderBlogs(cat, true)}>{cat}</li>
          ))}
        </ul>
      </div>
      <div className="blogs-sidebar__tags">
        <h3>Tags:</h3>
        {tags.map(tag => (
          <span onClick={() => renderBlogs(tag, false)}>{`${tag}, `}</span>
        ))}
      </div>
    </aside>
  )
}

export default Sidebar
