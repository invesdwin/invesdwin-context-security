package de.invesdwin.context.security.ldap.dao;

import java.util.Optional;

import javax.annotation.concurrent.ThreadSafe;
import javax.inject.Inject;
import javax.inject.Named;
import javax.naming.Name;
import javax.naming.ldap.LdapName;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.data.ldap.repository.LdapRepository;
import org.springframework.data.ldap.repository.support.SimpleLdapRepository;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.BaseLdapNameAware;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.support.LdapNameBuilder;

import de.invesdwin.util.assertions.Assertions;
import de.invesdwin.util.lang.reflection.Reflections;

@Named
@ThreadSafe
public abstract class ALdapDao<E> implements LdapRepository<E>, InitializingBean, BaseLdapNameAware {

    private final Class<E> genericType;
    private SimpleLdapRepository<E> delegate;

    private LdapName baseLdapPath;

    @Inject
    private LdapTemplate ldapTemplate;

    public ALdapDao() {
        this.genericType = findGenericType();
        Assertions.assertThat(genericType).isNotNull();
    }

    @Override
    public void setBaseLdapPath(final LdapName baseLdapPath) {
        this.baseLdapPath = baseLdapPath;
    }

    protected LdapName getBaseLdapPath() {
        return baseLdapPath;
    }

    protected LdapName getFullDn(final E entity) {
        return LdapNameBuilder.newInstance(baseLdapPath)
                .add(ldapTemplate.getObjectDirectoryMapper().getId(entity))
                .build();
    }

    protected LdapTemplate getLdapTemplate() {
        return ldapTemplate;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        this.delegate = new SimpleLdapRepository<E>(ldapTemplate, ldapTemplate.getObjectDirectoryMapper(), genericType);
    }

    /**
     * @see <a href="http://blog.xebia.com/2009/02/07/acessing-generic-types-at-runtime-in-java/">Source</a>
     */
    @SuppressWarnings("unchecked")
    protected Class<E> findGenericType() {
        return (Class<E>) Reflections.resolveTypeArguments(getClass(), ALdapDao.class)[0];
    }

    @Override
    public <S extends E> S save(final S entity) {
        return delegate.save(entity);
    }

    @Override
    public <S extends E> Iterable<S> saveAll(final Iterable<S> entities) {
        return delegate.saveAll(entities);
    }

    public E findOneById(final Name id) {
        return findById(id).orElse(null);
    }

    @Override
    public Optional<E> findById(final Name id) {
        return delegate.findById(id);
    }

    @Override
    public boolean existsById(final Name id) {
        return delegate.existsById(id);
    }

    @Override
    public Iterable<E> findAll() {
        return delegate.findAll();
    }

    @Override
    public Iterable<E> findAllById(final Iterable<Name> ids) {
        return delegate.findAllById(ids);
    }

    @Override
    public long count() {
        return delegate.count();
    }

    @Override
    public void deleteById(final Name id) {
        delegate.deleteById(id);
    }

    @Override
    public void delete(final E entity) {
        delegate.delete(entity);
    }

    @Override
    public void deleteAll(final Iterable<? extends E> entities) {
        delegate.deleteAll(entities);
    }

    @Override
    public void deleteAll() {
        delegate.deleteAll();
    }

    @Override
    public Optional<E> findOne(final LdapQuery ldapQuery) {
        return delegate.findOne(ldapQuery);
    }

    @Override
    public Iterable<E> findAll(final LdapQuery ldapQuery) {
        return delegate.findAll(ldapQuery);
    }

}
