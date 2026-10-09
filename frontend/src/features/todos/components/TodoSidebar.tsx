import React from 'react';
import { Box, Typography, Button, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Badge } from '@mui/material';
import { List as ListIcon, CheckCircle, AlertOctagon, Plus, type LucideIcon } from 'lucide-react';

type TodoFilter = 'all' | 'done' | 'important';

interface TodoSidebarProps {
  activeFilter: TodoFilter;
  setActiveFilter: (filter: TodoFilter) => void;
  counts: {
    all: number;
    done: number;
    important: number;
  };
  onNewTodo: () => void;
}

export const TodoSidebar: React.FC<TodoSidebarProps> = ({ activeFilter, setActiveFilter, counts, onNewTodo }) => {
  const menuItems: { id: TodoFilter; label: string; icon: LucideIcon; count: number; color: string }[] = [
    { id: 'all', label: 'Todo', icon: ListIcon, count: counts.all, color: '#00f3ff' },
    { id: 'done', label: 'Done', icon: CheckCircle, count: counts.done, color: '#00ff62' },
    { id: 'important', label: 'Important', icon: AlertOctagon, count: counts.important, color: '#ff003c' },
  ];

  return (
    <Box sx={{ width: 280, height: '100%', display: 'flex', flexDirection: 'column', gap: 4, pr: 2 }}>
      <List sx={{ flexGrow: 1 }}>
        {menuItems.map((item) => (
          <ListItem 
            key={item.id}
            disablePadding
            sx={{ mb: 1 }}
          >
            <ListItemButton
              onClick={() => setActiveFilter(item.id)}
              sx={{ 
                borderRadius: '12px',
                bgcolor: activeFilter === item.id ? 'rgba(0, 243, 255, 0.1)' : 'transparent',
                border: activeFilter === item.id ? '1px solid rgba(0, 243, 255, 0.2)' : '1px solid transparent',
                '&:hover': { bgcolor: 'rgba(255, 255, 255, 0.03)' },
                transition: 'all 0.3s ease'
              }}
            >
              <ListItemIcon sx={{ minWidth: 40, color: activeFilter === item.id ? item.color : 'text.secondary' }}>
                <item.icon size={20} />
              </ListItemIcon>
              <ListItemText 
                primary={
                  <Typography sx={{ 
                    fontFamily: 'Orbitron', 
                    fontSize: '0.75rem', 
                    fontWeight: 800,
                    color: activeFilter === item.id ? 'text.primary' : 'rgba(255,255,255,0.5)',
                    letterSpacing: 1
                  }}>
                    {item.label.toUpperCase()}
                  </Typography>
                } 
              />
              {item.count > 0 && (
                <Badge 
                  badgeContent={item.count} 
                  sx={{ 
                    '& .MuiBadge-badge': { 
                      bgcolor: item.color, 
                      color: '#000', 
                      fontWeight: 900,
                      fontFamily: 'Orbitron',
                      fontSize: '0.6rem',
                      boxShadow: `0 0 10px ${item.color}`
                    } 
                  }} 
                />
              )}
            </ListItemButton>
          </ListItem>
        ))}
      </List>

      <Button
        variant="contained"
        fullWidth
        startIcon={<Plus size={18} />}
        onClick={onNewTodo}
        sx={{
          bgcolor: '#3f51b5', // Blue color like in the image
          color: '#fff',
          fontFamily: 'Orbitron',
          fontWeight: 900,
          fontSize: '0.7rem',
          letterSpacing: 1,
          py: 1.5,
          borderRadius: '8px',
          boxShadow: '0 4px 15px rgba(63, 81, 181, 0.4)',
          '&:hover': { bgcolor: '#303f9f', boxShadow: '0 6px 20px rgba(63, 81, 181, 0.6)' }
        }}
      >
        NEW TODO
      </Button>
    </Box>
  );
};
