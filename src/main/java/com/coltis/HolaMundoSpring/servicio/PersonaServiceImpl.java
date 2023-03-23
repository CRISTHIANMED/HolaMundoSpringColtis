package com.coltis.HolaMundoSpring.servicio;

import com.coltis.HolaMundoSpring.dao.PersonaDao;
import com.coltis.HolaMundoSpring.domain.Persona;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PersonaServiceImpl implements PersonaService {

    @Autowired
    private PersonaDao PersonaDao;

    @Override
    @Transactional(readOnly = true)
    public List<Persona> listarPersonas() {
        return (List<Persona>) PersonaDao.findAll();
    }

    @Override
    @Transactional
    public void guardar(Persona persona) {
        PersonaDao.save(persona);
    }

    @Override
    @Transactional
    public void eliminar(Persona persona) {
        PersonaDao.delete(persona);
    }

    @Override
    @Transactional(readOnly = true)
    public Persona encontrarPersona(Persona persona) {
        return PersonaDao.findById(persona.getIdPersona()).orElse(null);
    }

}
